#include "birch/guard/model_lowering.h"

#include "birch/dex/builder.h"
#include "birch/dex/code.h"
#include "birch/dex/cloner.h"
#include "birch/dex/remap.h"
#include "birch/dex/verifier.h"
#include "birch/guard/scope.h"
#include "birch/guard/constant_runtime.h"
#include "birch/guard/opaque_runtime.h"
#include "birch/guard/string_runtime.h"
#include "birch/utils/hash.h"

#include <algorithm>
#include <array>
#include <bit>
#include <cmath>
#include <iomanip>
#include <limits>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string_view>
#include <map>
#include <span>
#include <iterator>
#include <type_traits>
#include <utility>

#include "model_classes.h"
#include "model_support.h"

namespace birch::guard::detail {
namespace {

void RewriteEncodedValueMethods(
    dex::EncodedValueSpec& value,
    const std::map<std::string, dex::MethodReference, std::less<>>& remap);


void RewriteEncodedAnnotationMethods(
    dex::EncodedAnnotationSpec& annotation,
    const std::map<std::string, dex::MethodReference, std::less<>>& remap) {
    for (auto& element : annotation.elements) {
        RewriteEncodedValueMethods(element.value, remap);
    }
}


void RewriteEncodedValueMethods(
    dex::EncodedValueSpec& value,
    const std::map<std::string, dex::MethodReference, std::less<>>& remap) {
    std::visit(
        [&](auto& item) {
            using Item = std::decay_t<decltype(item)>;
            if constexpr (std::is_same_v<Item, dex::MethodReference>) {
                if (const auto found = remap.find(MethodIdentity(item));
                    found != remap.end()) {
                    item = found->second;
                }
            } else if constexpr (std::is_same_v<Item,
                                                dex::MethodHandleReference>) {
                if (auto* method = std::get_if<dex::MethodReference>(&item.member)) {
                    if (const auto found = remap.find(MethodIdentity(*method));
                        found != remap.end()) {
                        *method = found->second;
                    }
                }
            } else if constexpr (std::is_same_v<Item,
                                                std::shared_ptr<dex::EncodedArraySpec>>) {
                if (item) {
                    for (auto& child : item->values) {
                        RewriteEncodedValueMethods(child, remap);
                    }
                }
            } else if constexpr (std::is_same_v<Item,
                                                std::shared_ptr<dex::EncodedAnnotationSpec>>) {
                if (item) RewriteEncodedAnnotationMethods(*item, remap);
            }
        },
        value.value);
}


void RewriteAnnotationMethods(
    dex::AnnotationSpec& annotation,
    const std::map<std::string, dex::MethodReference, std::less<>>& remap) {
    RewriteEncodedAnnotationMethods(annotation.annotation, remap);
}


void RewriteClassMethodReferences(
    dex::ClassSpec& klass,
    const std::map<std::string, dex::MethodReference, std::less<>>& remap) {
    for (auto& annotation : klass.annotations) RewriteAnnotationMethods(annotation, remap);
    for (auto* fields : {&klass.static_fields, &klass.instance_fields}) {
        for (auto& field : *fields) {
            for (auto& annotation : field.annotations) {
                RewriteAnnotationMethods(annotation, remap);
            }
            if (field.static_value.has_value()) {
                RewriteEncodedValueMethods(*field.static_value, remap);
            }
        }
    }
    for (auto* methods : {&klass.direct_methods, &klass.virtual_methods}) {
        for (auto& method : *methods) {
            for (auto& annotation : method.annotations) {
                RewriteAnnotationMethods(annotation, remap);
            }
            for (auto& annotations : method.parameter_annotations) {
                for (auto& annotation : annotations) {
                    RewriteAnnotationMethods(annotation, remap);
                }
            }
            if (method.body.invoke_reference.has_value()) {
                if (const auto found = remap.find(
                        MethodIdentity(*method.body.invoke_reference));
                    found != remap.end()) {
                    method.body.invoke_reference = found->second;
                }
            }
            for (auto& patch : method.body.invoke_references) {
                if (const auto found = remap.find(MethodIdentity(patch.reference));
                    found != remap.end()) {
                    patch.reference = found->second;
                }
            }
            for (auto& patch : method.body.references) {
                if (auto* reference =
                        std::get_if<dex::MethodReference>(&patch.reference)) {
                    if (const auto found = remap.find(MethodIdentity(*reference));
                        found != remap.end()) {
                        *reference = found->second;
                    }
                } else if (auto* handle =
                               std::get_if<dex::MethodHandleReference>(
                                   &patch.reference)) {
                    if (auto* method_reference =
                            std::get_if<dex::MethodReference>(&handle->member)) {
                        if (const auto found = remap.find(
                                MethodIdentity(*method_reference));
                            found != remap.end()) {
                            *method_reference = found->second;
                        }
                    }
                } else if (auto* call_site =
                               std::get_if<dex::CallSiteReference>(&patch.reference)) {
                    if (call_site->values) {
                        for (auto& value : call_site->values->values) {
                            RewriteEncodedValueMethods(value, remap);
                        }
                    }
                }
            }
        }
    }
}


bool EncodedValueMentionsType(const dex::EncodedValueSpec& value,
                              std::string_view descriptor);


bool EncodedAnnotationMentionsType(const dex::EncodedAnnotationSpec& annotation,
                                   std::string_view descriptor) {
    if (annotation.type == descriptor) return true;
    return std::any_of(annotation.elements.begin(), annotation.elements.end(),
                       [&](const auto& element) {
                           return EncodedValueMentionsType(element.value, descriptor);
                       });
}


bool EncodedValueMentionsType(const dex::EncodedValueSpec& value,
                              std::string_view descriptor) {
    return std::visit(
        [&](const auto& item) {
            using Item = std::decay_t<decltype(item)>;
            if constexpr (std::is_same_v<Item, dex::TypeReference>) {
                return item.descriptor == descriptor;
            } else if constexpr (std::is_same_v<Item, dex::FieldReference>) {
                return item.owner == descriptor || item.type == descriptor;
            } else if constexpr (std::is_same_v<Item, dex::MethodReference>) {
                if (item.owner == descriptor || item.return_type == descriptor) return true;
                return std::find(item.parameter_types.begin(), item.parameter_types.end(),
                                 descriptor) != item.parameter_types.end();
            } else if constexpr (std::is_same_v<Item, dex::ProtoReference>) {
                if (item.return_type == descriptor) return true;
                return std::find(item.parameter_types.begin(), item.parameter_types.end(),
                                 descriptor) != item.parameter_types.end();
            } else if constexpr (std::is_same_v<Item, dex::MethodHandleReference>) {
                if (const auto* field = std::get_if<dex::FieldReference>(&item.member)) {
                    return field->owner == descriptor || field->type == descriptor;
                }
                const auto& method = std::get<dex::MethodReference>(item.member);
                if (method.owner == descriptor || method.return_type == descriptor) return true;
                return std::find(method.parameter_types.begin(), method.parameter_types.end(),
                                 descriptor) != method.parameter_types.end();
            } else if constexpr (std::is_same_v<Item, dex::CallSiteReference>) {
                if (!item.values) return false;
                return std::any_of(item.values->values.begin(), item.values->values.end(),
                                   [&](const auto& child) {
                                       return EncodedValueMentionsType(child, descriptor);
                                   });
            } else if constexpr (std::is_same_v<Item,
                                                std::shared_ptr<dex::EncodedArraySpec>>) {
                if (!item) return false;
                return std::any_of(item->values.begin(), item->values.end(),
                                   [&](const auto& child) {
                                       return EncodedValueMentionsType(child, descriptor);
                                   });
            } else if constexpr (std::is_same_v<Item,
                                                std::shared_ptr<dex::EncodedAnnotationSpec>>) {
                return item && EncodedAnnotationMentionsType(*item, descriptor);
            } else {
                return false;
            }
        },
        value.value);
}


bool TypeListContains(std::string_view descriptor,
                      const std::vector<std::string>& types) {
    return std::find(types.begin(), types.end(), descriptor) != types.end();
}


bool BodyMentionsType(const dex::MethodSpec& method, std::string_view descriptor,
                      bool allow_method_owner) {
    (void)allow_method_owner;
    if (method.return_type == descriptor ||
        TypeListContains(descriptor, method.parameter_types)) {
        return true;
    }
    for (const auto& patch : method.body.references) {
        const auto mentioned = std::visit(
            [&](const auto& item) {
                using Item = std::decay_t<decltype(item)>;
                if constexpr (std::is_same_v<Item, std::string>) {
                    return item == descriptor;
                } else if constexpr (std::is_same_v<Item, dex::TypeReference>) {
                    return item.descriptor == descriptor;
                } else if constexpr (std::is_same_v<Item, dex::FieldReference>) {
                    return item.owner == descriptor || item.type == descriptor;
                } else if constexpr (std::is_same_v<Item, dex::MethodReference>) {
                    // A method owner is precisely the reference class
                    // merging rewrites.  It is not a type-identity use.
                    if (item.owner == descriptor) return false;
                    if (item.return_type == descriptor) return true;
                    return TypeListContains(descriptor, item.parameter_types);
                } else if constexpr (std::is_same_v<Item, dex::ProtoReference>) {
                    if (item.return_type == descriptor) return true;
                    return TypeListContains(descriptor, item.parameter_types);
                } else if constexpr (std::is_same_v<Item, dex::MethodHandleReference>) {
                    if (const auto* field = std::get_if<dex::FieldReference>(&item.member)) {
                        return field->owner == descriptor || field->type == descriptor;
                    }
                    const auto& target = std::get<dex::MethodReference>(item.member);
                    if (target.owner == descriptor) return false;
                    if (target.return_type == descriptor) return true;
                    return TypeListContains(descriptor, target.parameter_types);
                } else if constexpr (std::is_same_v<Item, dex::CallSiteReference>) {
                    if (!item.values) return false;
                    return std::any_of(item.values->values.begin(), item.values->values.end(),
                                       [&](const auto& child) {
                                           return EncodedValueMentionsType(child, descriptor);
                                       });
                } else {
                    return false;
                }
            },
            patch.reference);
        if (mentioned) return true;
    }
    return false;
}


bool ClassHasForbiddenType(const dex::ClassSpec& klass,
                           std::string_view descriptor,
                           bool allow_method_owner) {
    if (klass.superclass == descriptor ||
        std::find(klass.interfaces.begin(), klass.interfaces.end(), descriptor) !=
            klass.interfaces.end()) {
        return true;
    }
    for (const auto* fields : {&klass.static_fields, &klass.instance_fields}) {
        for (const auto& field : *fields) {
            if (field.type == descriptor) return true;
            if (field.static_value.has_value() &&
                EncodedValueMentionsType(*field.static_value, descriptor)) {
                return true;
            }
            if (std::any_of(field.annotations.begin(), field.annotations.end(),
                            [&](const auto& annotation) {
                                return EncodedAnnotationMentionsType(
                                    annotation.annotation, descriptor);
                            })) {
                return true;
            }
        }
    }
    if (std::any_of(klass.annotations.begin(), klass.annotations.end(),
                    [&](const auto& annotation) {
                        return EncodedAnnotationMentionsType(annotation.annotation,
                                                             descriptor);
                    })) {
        return true;
    }
    for (const auto* methods : {&klass.direct_methods, &klass.virtual_methods}) {
        for (const auto& method : *methods) {
            if (BodyMentionsType(method, descriptor, allow_method_owner)) return true;
            if (method.body.invoke_reference.has_value()) {
                const auto& target = *method.body.invoke_reference;
                if (target.owner == descriptor) {
                    // Method owner references can be rewritten during class
                    // merging; they do not by themselves expose a type.
                } else if (target.return_type == descriptor ||
                           TypeListContains(descriptor, target.parameter_types)) {
                    return true;
                }
            }
            for (const auto& patch : method.body.invoke_references) {
                const auto& target = patch.reference;
                if (target.owner == descriptor) {
                    // See the invoke_reference case above.
                } else if (target.return_type == descriptor ||
                           TypeListContains(descriptor, target.parameter_types)) {
                    return true;
                }
            }
            if (std::any_of(method.annotations.begin(), method.annotations.end(),
                            [&](const auto& annotation) {
                                return EncodedAnnotationMentionsType(
                                    annotation.annotation, descriptor);
                            })) {
                return true;
            }
        }
    }
    return false;
}


bool IsPlainStaticUtility(const dex::ClassSpec& klass) {
    if ((klass.access_flags & (kInterface | kAbstract | kEnum)) != 0U ||
        (klass.superclass.has_value() && *klass.superclass != "Ljava/lang/Object;") ||
        !klass.interfaces.empty() || !klass.static_fields.empty() ||
        !klass.instance_fields.empty()) {
        return false;
    }
    for (const auto& method : klass.direct_methods) {
        if ((method.access_flags & kStatic) == 0U ||
            (method.access_flags & (kNative | kAbstract)) != 0U ||
            method.name == "<init>" || method.name == "<clinit>" ||
            method.body.code_units.empty()) {
            return false;
        }
    }
    return std::all_of(klass.virtual_methods.begin(), klass.virtual_methods.end(),
                       [](const auto&) { return false; });
}


bool IsAbstractInterfaceCandidate(const dex::ClassSpec& klass) {
    if ((klass.access_flags & kInterface) == 0U ||
        (klass.access_flags & 0x2000U) != 0U ||
        !klass.static_fields.empty() || !klass.instance_fields.empty()) {
        return false;
    }
    for (const auto* methods : {&klass.direct_methods, &klass.virtual_methods}) {
        for (const auto& method : *methods) {
            if ((method.access_flags & kAbstract) == 0U ||
                (method.access_flags & (kStatic | kNative)) != 0U ||
                !method.body.code_units.empty()) {
                return false;
            }
        }
    }
    return true;
}


bool IsTrivialObjectConstructor(const dex::MethodSpec& method) {
    if (method.name != "<init>" || method.return_type != "V" ||
        !method.parameter_types.empty() || method.body.code_units.size() != 4U ||
        (method.body.code_units.front() & 0xffU) != 0x70U ||
        (method.body.code_units.back() & 0xffU) != 0x0eU ||
        method.body.references.size() != 1U) {
        return false;
    }
    const auto* target = std::get_if<dex::MethodReference>(
        &method.body.references.front().reference);
    return target != nullptr && target->owner == "Ljava/lang/Object;" &&
        target->name == "<init>" && target->return_type == "V" &&
        target->parameter_types.empty();
}


bool IsInterfaceCandidate(const dex::ClassSpec& klass) {
    if ((klass.access_flags & (kInterface | kAbstract)) != kAbstract ||
        (klass.superclass.has_value() && *klass.superclass != "Ljava/lang/Object;") ||
        !klass.static_fields.empty() ||
        !klass.instance_fields.empty()) {
        return false;
    }
    for (const auto& method : klass.direct_methods) {
        if (!IsTrivialObjectConstructor(method)) return false;
    }
    for (const auto& method : klass.virtual_methods) {
        if ((method.access_flags & (kAbstract | kStatic | kNative)) != kAbstract ||
            !method.body.code_units.empty()) {
            return false;
        }
    }
    return true;
}


bool EncodedValueHasMethodHandleOwner(const dex::EncodedValueSpec& value,
                                      std::string_view descriptor);


bool AnnotationHasMethodHandleOwner(
    const dex::EncodedAnnotationSpec& annotation,
    std::string_view descriptor) {
    return std::any_of(annotation.elements.begin(), annotation.elements.end(),
                       [&](const auto& element) {
                           return EncodedValueHasMethodHandleOwner(
                               element.value, descriptor);
                       });
}


bool EncodedValueHasMethodHandleOwner(const dex::EncodedValueSpec& value,
                                      std::string_view descriptor) {
    return std::visit(
        [&](const auto& item) {
            using Item = std::decay_t<decltype(item)>;
            if constexpr (std::is_same_v<Item, dex::MethodHandleReference>) {
                const auto* method = std::get_if<dex::MethodReference>(
                    &item.member);
                return method != nullptr && method->owner == descriptor;
            } else if constexpr (std::is_same_v<
                                     Item,
                                     std::shared_ptr<dex::EncodedArraySpec>>) {
                return item && std::any_of(
                    item->values.begin(), item->values.end(),
                    [&](const auto& child) {
                        return EncodedValueHasMethodHandleOwner(
                            child, descriptor);
                    });
            } else if constexpr (std::is_same_v<
                                     Item,
                                     std::shared_ptr<dex::EncodedAnnotationSpec>>) {
                return item && AnnotationHasMethodHandleOwner(
                    *item, descriptor);
            } else if constexpr (std::is_same_v<Item,
                                                 dex::CallSiteReference>) {
                return item.values && std::any_of(
                    item.values->values.begin(), item.values->values.end(),
                    [&](const auto& child) {
                        return EncodedValueHasMethodHandleOwner(
                            child, descriptor);
                    });
            } else {
                return false;
            }
        },
        value.value);
}


bool HasUnrewritableMethodHandle(
    const std::vector<dex::ClassSpec>& classes,
    std::string_view descriptor) {
    const auto annotations_contain = [&](const auto& annotations) {
        return std::any_of(annotations.begin(), annotations.end(),
                           [&](const auto& annotation) {
                               return AnnotationHasMethodHandleOwner(
                                   annotation.annotation, descriptor);
                           });
    };
    for (const auto& klass : classes) {
        if (annotations_contain(klass.annotations)) return true;
        for (const auto* fields : {&klass.static_fields,
                                   &klass.instance_fields}) {
            for (const auto& field : *fields) {
                if (field.static_value.has_value() &&
                    EncodedValueHasMethodHandleOwner(
                        *field.static_value, descriptor)) {
                    return true;
                }
                if (annotations_contain(field.annotations)) return true;
            }
        }
        for (const auto* methods : {&klass.direct_methods,
                                    &klass.virtual_methods}) {
            for (const auto& method : *methods) {
                if (annotations_contain(method.annotations)) return true;
                for (const auto& parameter : method.parameter_annotations) {
                    if (annotations_contain(parameter)) return true;
                }
                for (const auto& patch : method.body.references) {
                    if (const auto* handle =
                            std::get_if<dex::MethodHandleReference>(
                                &patch.reference)) {
                        const auto* target =
                            std::get_if<dex::MethodReference>(
                                &handle->member);
                        if (target != nullptr &&
                            target->owner == descriptor) {
                            return true;
                        }
                    }
                    if (const auto* site =
                            std::get_if<dex::CallSiteReference>(
                                &patch.reference);
                        site != nullptr && site->values != nullptr) {
                        for (const auto& value : site->values->values) {
                            if (EncodedValueHasMethodHandleOwner(
                                    value, descriptor)) {
                                return true;
                            }
                        }
                    }
                }
            }
        }
    }
    return false;
}


bool RewriteInvokeKind(dex::MethodBodySpec& body,
                       std::string_view owner,
                       std::uint8_t short_from,
                       std::uint8_t short_to,
                       std::uint8_t range_from,
                       std::uint8_t range_to,
                       bool apply) {
    bool valid = true;
    std::set<std::uint32_t> rewritten;
    const auto rewrite = [&](const dex::MethodReference& reference,
                             std::uint32_t code_unit) {
        if (reference.owner != owner || reference.name == "<init>") return;
        if (code_unit == 0U || code_unit > body.code_units.size()) {
            valid = false;
            return;
        }
        const auto opcode_unit = code_unit - 1U;
        if (!rewritten.insert(opcode_unit).second) return;
        const auto opcode = static_cast<std::uint8_t>(
            body.code_units[opcode_unit] & 0xffU);
        if (opcode == short_from) {
            if (apply) {
                body.code_units[opcode_unit] = static_cast<std::uint16_t>(
                    (body.code_units[opcode_unit] & 0xff00U) | short_to);
            }
        } else if (opcode == range_from) {
            if (apply) {
                body.code_units[opcode_unit] = static_cast<std::uint16_t>(
                    (body.code_units[opcode_unit] & 0xff00U) | range_to);
            }
        } else {
            valid = false;
        }
    };
    if (body.invoke_reference.has_value()) {
        rewrite(*body.invoke_reference, body.invoke_reference_unit);
    }
    for (const auto& patch : body.invoke_references) {
        rewrite(patch.reference, patch.code_unit);
    }
    for (const auto& patch : body.references) {
        if (const auto* reference = std::get_if<dex::MethodReference>(
                &patch.reference)) {
            rewrite(*reference, patch.code_unit);
        }
    }
    return valid;
}


bool RewriteContractInvocations(std::vector<dex::ClassSpec>& classes,
                                std::string_view owner,
                                bool to_interface) {
    for (const auto apply : {false, true}) {
        for (auto& klass : classes) {
            for (auto* methods : {&klass.direct_methods,
                                  &klass.virtual_methods}) {
                for (auto& method : *methods) {
                    if (!RewriteInvokeKind(
                            method.body, owner,
                            to_interface ? 0x6eU : 0x72U,
                            to_interface ? 0x72U : 0x6eU,
                            to_interface ? 0x74U : 0x78U,
                            to_interface ? 0x78U : 0x74U,
                            apply)) {
                        return false;
                    }
                }
            }
        }
    }
    return true;
}


void RewriteConstructorOwner(dex::ClassSpec& klass,
                             std::string_view old_owner,
                             std::string_view new_owner) {
    for (auto& method : klass.direct_methods) {
        if (method.name != "<init>") continue;
        const auto rewrite = [&](dex::MethodReference& reference) {
            if (reference.owner == old_owner &&
                reference.name == "<init>") {
                reference.owner = std::string(new_owner);
            }
        };
        if (method.body.invoke_reference.has_value()) {
            rewrite(*method.body.invoke_reference);
        }
        for (auto& patch : method.body.invoke_references) {
            rewrite(patch.reference);
        }
        for (auto& patch : method.body.references) {
            if (auto* reference = std::get_if<dex::MethodReference>(
                    &patch.reference)) {
                rewrite(*reference);
            }
        }
    }
}


dex::MethodSpec BuildDefaultConstructor(std::string_view owner) {
    dex::MethodSpec constructor;
    constructor.name = "<init>";
    constructor.return_type = "V";
    constructor.access_flags = 0x0001U;
    constructor.body.registers_size = 1U;
    constructor.body.ins_size = 1U;
    constructor.body.outs_size = 1U;
    AppendInvoke35c(constructor.body.code_units, 0x70U, {0U},
                    constructor.body,
                    {"Ljava/lang/Object;", "<init>", "V", {}});
    constructor.body.code_units.push_back(0x000eU);
    (void)owner;
    return constructor;
}


} // namespace

std::size_t ModelClassStructure::MergeStaticUtilityClasses(
    std::vector<dex::ClassSpec>& classes, const GuardConfig& config,
    ModelLoweringResult& report) {
    const auto& pass = config.passes.at("structure.class_merging");
    if (!pass.enabled || classes.size() < 2U) return 0U;
    const ScopeMatcher scope(config.scope);
    std::vector<bool> removed(classes.size(), false);
    std::map<std::string, dex::MethodReference, std::less<>> method_remap;
    std::size_t merged = 0U;
    for (std::size_t source_index = 0U; source_index < classes.size(); ++source_index) {
        auto& source = classes[source_index];
        if (removed[source_index] || !scope.IsProtected(source.descriptor) ||
            !scope.AllowsCodeTransforms(source.descriptor) ||
            !IsPlainStaticUtility(source) ||
            !Selected(pass, config.seed, source.descriptor, 0x4d455247U)) {
            continue;
        }
        // A removed class may only be mentioned through method owners.  Any
        // type/signature/field mention would make class identity observable.
        bool externally_typed = false;
        for (std::size_t index = 0U; index < classes.size(); ++index) {
            if (removed[index]) continue;
            const auto allow_method_owner = index == source_index;
            if (ClassHasForbiddenType(classes[index], source.descriptor,
                                       allow_method_owner)) {
                // Method owner references in the source class are explicitly
                // allowed by BodyMentionsType; every other hit is a type use.
                externally_typed = true;
                break;
            }
        }
        if (externally_typed) continue;
        std::size_t target_index = classes.size();
        for (std::size_t index = 0U; index < classes.size(); ++index) {
            if (index == source_index || removed[index] ||
                !scope.IsProtected(classes[index].descriptor) ||
                !scope.AllowsCodeTransforms(classes[index].descriptor) ||
                !IsPlainStaticUtility(classes[index])) {
                continue;
            }
            if (!Selected(pass, config.seed, classes[index].descriptor,
                          0x54415247U ^ source_index)) {
                continue;
            }
            target_index = index;
            break;
        }
        if (target_index == classes.size()) continue;
        auto& target = classes[target_index];
        std::set<std::string, std::less<>> used_names;
        for (const auto& method : target.direct_methods) used_names.insert(method.name);
        std::vector<dex::MethodSpec> moved;
        moved.reserve(source.direct_methods.size());
        for (auto& method : source.direct_methods) {
            const auto old = MethodReferenceFor(source, method);
            auto name = method.name;
            bool conflict = std::any_of(target.direct_methods.begin(),
                                        target.direct_methods.end(),
                                        [&](const auto& existing) {
                                            return existing.name == name &&
                                                existing.return_type == method.return_type &&
                                                existing.parameter_types == method.parameter_types;
                                        });
            if (conflict) name = SyntheticName(config.seed, "merge", moved.size(), used_names);
            used_names.insert(name);
            dex::MethodReference rewritten{target.descriptor, name,
                                           method.return_type, method.parameter_types};
            method_remap.emplace(MethodIdentity(old), rewritten);
            method.name = std::move(name);
            moved.push_back(std::move(method));
        }
        for (auto& method : moved) target.direct_methods.push_back(std::move(method));
        removed[source_index] = true;
        ++merged;
    }
    if (merged == 0U) return 0U;
    for (auto& klass : classes) RewriteClassMethodReferences(klass, method_remap);
    std::vector<dex::ClassSpec> kept;
    kept.reserve(classes.size() - merged);
    for (std::size_t index = 0U; index < classes.size(); ++index) {
        if (!removed[index]) kept.push_back(std::move(classes[index]));
    }
    classes = std::move(kept);
    report.merged_classes += merged;
    report.pass_applications["structure.class_merging"] += merged;
    return merged;
}


std::size_t ModelClassStructure::ConvertInterfaceAbstractClasses(
    std::vector<dex::ClassSpec>& classes, const GuardConfig& config,
    ModelLoweringResult& report) {
    const auto& pass = config.passes.at("structure.interface_abstract_conversion");
    if (!pass.enabled) return 0U;
    const ScopeMatcher scope(config.scope);
    std::size_t converted = 0U;
    for (std::size_t index = 0U; index < classes.size(); ++index) {
        auto& klass = classes[index];
        if (!scope.IsProtected(klass.descriptor) ||
            !scope.AllowsCodeTransforms(klass.descriptor) ||
            !Selected(pass, config.seed, klass.descriptor, 0x494e5446U)) {
            continue;
        }
        const auto is_interface = (klass.access_flags & kInterface) != 0U;
        if (is_interface && IsAbstractInterfaceCandidate(klass) &&
            !HasUnrewritableMethodHandle(classes, klass.descriptor)) {
            std::vector<std::size_t> implementors;
            bool legal = true;
            for (std::size_t other = 0U; other < classes.size(); ++other) {
                if (other == index) continue;
                auto& candidate = classes[other];
                if (candidate.superclass == klass.descriptor) {
                    legal = false;
                    break;
                }
                if (std::find(candidate.interfaces.begin(),
                              candidate.interfaces.end(),
                              klass.descriptor) ==
                    candidate.interfaces.end()) {
                    continue;
                }
                if ((candidate.access_flags & kInterface) != 0U ||
                    !candidate.superclass.has_value() ||
                    *candidate.superclass != "Ljava/lang/Object;") {
                    legal = false;
                    break;
                }
                implementors.push_back(other);
            }
            if (!legal || !RewriteContractInvocations(
                    classes, klass.descriptor, false)) {
                continue;
            }
            klass.access_flags = (klass.access_flags & ~kInterface) | kAbstract;
            klass.access_flags &= ~0x0010U; // abstract classes cannot be final
            klass.direct_methods.push_back(
                BuildDefaultConstructor(klass.descriptor));
            for (const auto implementor : implementors) {
                auto& child = classes[implementor];
                child.interfaces.erase(
                    std::remove(child.interfaces.begin(),
                                child.interfaces.end(), klass.descriptor),
                    child.interfaces.end());
                child.superclass = klass.descriptor;
                RewriteConstructorOwner(child, "Ljava/lang/Object;",
                                        klass.descriptor);
            }
            ++converted;
            continue;
        }
        if (!is_interface && IsInterfaceCandidate(klass) &&
            !HasUnrewritableMethodHandle(classes, klass.descriptor)) {
            std::vector<std::size_t> subclasses;
            bool legal = true;
            for (std::size_t other = 0U; other < classes.size(); ++other) {
                if (other == index) continue;
                if (std::find(classes[other].interfaces.begin(),
                              classes[other].interfaces.end(),
                              klass.descriptor) !=
                    classes[other].interfaces.end()) {
                    legal = false;
                    break;
                }
                if (classes[other].superclass == klass.descriptor) {
                    subclasses.push_back(other);
                }
            }
            if (!legal || !RewriteContractInvocations(
                    classes, klass.descriptor, true)) {
                continue;
            }
            for (const auto subclass : subclasses) {
                auto& child = classes[subclass];
                child.superclass = "Ljava/lang/Object;";
                child.interfaces.push_back(klass.descriptor);
                RewriteConstructorOwner(child, klass.descriptor,
                                        "Ljava/lang/Object;");
            }
            klass.direct_methods.clear();
            for (auto& method : klass.virtual_methods) {
                method.access_flags &= ~(0x0002U | 0x0004U | 0x0010U);
                method.access_flags |= 0x0001U | kAbstract;
            }
            klass.access_flags = (klass.access_flags | kInterface | kAbstract) & ~0x0010U;
            ++converted;
        }
    }
    report.converted_classes += converted;
    report.pass_applications[
        "structure.interface_abstract_conversion"] += converted;
    return converted;
}


void ModelClassStructure::SplitStaticMethods(
    dex::ClassSpec& klass, const GuardConfig& config, ModelLoweringResult& report,
    std::vector<dex::ClassSpec>& generated_classes,
    std::set<std::string, std::less<>>& used_descriptors) {
    const auto& pass = config.passes.at("structure.class_splitting");
    if (!pass.enabled) return;
    std::size_t ordinal = 0U;
    const auto original_count = klass.direct_methods.size();
    for (std::size_t index = 0U; index < original_count; ++index, ++ordinal) {
        auto& method = klass.direct_methods[index];
        if (!Selected(pass, config.seed, klass.descriptor + "->" + method.name,
                      0x434c4153U) ||
            (method.access_flags & kStatic) == 0U ||
            !HasTransformableBody(method)) {
            continue;
        }
        bool references_private_source = false;
        if (method.body.invoke_reference.has_value()) {
            references_private_source =
                method.body.invoke_reference->owner == klass.descriptor;
        }
        for (const auto& patch : method.body.invoke_references) {
            references_private_source = references_private_source ||
                patch.reference.owner == klass.descriptor;
        }
        for (const auto& patch : method.body.references) {
            std::visit([&](const auto& reference) {
                using Reference = std::decay_t<decltype(reference)>;
                if constexpr (std::is_same_v<Reference, dex::FieldReference> ||
                              std::is_same_v<Reference, dex::MethodReference>) {
                    references_private_source = references_private_source ||
                        reference.owner == klass.descriptor;
                }
            }, patch.reference);
        }
        if (references_private_source) {
            ++report.skipped_methods;
            continue;
        }
        const auto companion_descriptor = SyntheticClassDescriptor(
            "class-split", klass.descriptor, config.seed, ordinal,
            used_descriptors);
        used_descriptors.insert(companion_descriptor);
        dex::ClassSpec companion;
        companion.descriptor = companion_descriptor;
        companion.access_flags = 0x1011U; // public final synthetic
        dex::MethodSpec moved;
        moved.name = method.name;
        moved.return_type = method.return_type;
        moved.parameter_types = method.parameter_types;
        moved.access_flags = 0x1009U; // public static synthetic
        moved.body = std::move(method.body);
        companion.direct_methods.push_back(std::move(moved));
        const auto target = companion.direct_methods.front();
        method.body = BuildWrapperBody(klass, method, target, std::nullopt,
                                       companion_descriptor);
        generated_classes.push_back(std::move(companion));
        ++report.split_methods;
        ++report.split_classes;
        ++report.pass_applications["structure.class_splitting"];
    }
}


} // namespace birch::guard::detail
