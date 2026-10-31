#include "technique_catalog.h"
#include <algorithm>
#include <utility>

namespace birch::guard::detail {
namespace {
using Entry = std::pair<std::string_view, std::string_view>;
constexpr std::string_view kStringCipher =
    "Custom reversible UTF-16 cipher (NOT AES/ChaCha): per-literal hash-derived 16-bit k1/k2/k3; "
    "4 base modes: ((u XOR k1)+k2) XOR k3; ((u+k1) XOR k2)+k3; "
    "(((u XOR k1) XOR index)+k2) XOR k3; (((u+k1) XOR k2)+k3) XOR k1. "
    "Then 8 rounds r=0..7: u=((u XOR uint16(index+17*r)) + uint16(k1+0x1357*r)) "
    "XOR uint16(k2 XOR (k3+0x246d*r)); all unit arithmetic modulo 65536. "
    "Generated DEX helpers apply inverse operations in reverse order; MUTF-8, NUL, "
    "surrogates and String.intern identity preserved. Keys ship in APK: not cryptographic secrecy.";
constexpr Entry kEntries[] = {
    {"rename.classes", "Cross-DEX class descriptor rewrite; seeded identifier dictionary, namespace collision reservation, manifest/XML/reflection closure and runtime-contract keep rules."},
    {"rename.methods", "Hierarchy-aware method renaming; override families share names, constructors/framework/native/reflection contracts retained, invoke/method-handle references relocated."},
    {"rename.fields", "Field name and reference rewriting with owner/type resolution, inherited-field collision checks and reflective/runtime keep contracts."},
    {"rename.parameters", "Rewrite debug parameter-name metadata to seeded $p identifiers; parameter types, word layout and invocation signature unchanged."},
    {"rename.packages", "Relocate eligible class descriptors to seeded package names; lock package-private access groups and update APK class-name references."},
    {"rename.overload_induction", "Reuse method names across legal distinct prototypes; preserve override families and reject duplicate-signature/inheritance conflicts."},
    {"structure.package_flattening", "Flatten eligible descriptor package paths subject to package-access locks; not an unconditional relocation of every class."},
    {"structure.method_splitting", "Retain original body in a private fragment and insert seeded XOR/add state-carrying fragment hops with an extra int parameter; typed wrappers preserve calling convention."},
    {"structure.method_outlining", "Move eligible method bodies to private synthetic helpers; original typed methods forward arguments and return values, without extracting arbitrary unsafe CFG regions."},
    {"structure.method_inlining", "Inline eligible trivial methods at compatible invoke sites with register/reference relocation; reject unsupported try, access and invocation shapes."},
    {"structure.class_splitting", "Move eligible static method bodies to generated companion classes and leave forwarding wrappers; retain methods with unsafe source-private/super dependencies."},
    {"structure.class_merging", "Merge eligible plain static utility classes; rewrite references and annotations, resolve member collisions and preserve initialization/access contracts."},
    {"structure.interface_abstract_conversion", "Convert restricted interface/abstract-class shapes with matching implementor superclass/constructor and invoke-kind rewrites; unsupported hierarchies and method handles retained."},
    {"structure.proxy_stubs", "Insert generated cross-class static forwarding stubs; instance receiver becomes an explicit typed argument, original body remains in a synthetic helper."},
    {"reflection.indirect_targets", "Replace eligible reflective API invokes with generated typed proxy methods; preserve receiver/arguments and relocate target references, not arbitrary reflective execution."},
    {"loading.encrypted_paths", kStringCipher},
    {"cfg.flattening", "Verifier-domain-aware keyed state-machine CFF; seeded physical layout, sparse/packed switch routing, typed transitions and runtime state barriers. Shared domains use expanded-CFG liveness; explicit monitor methods remain separate."},
    {"cfg.nested_flattening", "Layer state dispatch through independently keyed bucket dispatchers; business states retain type-safe per-domain routes, not repeated empty goto islands."},
    {"cfg.multi_state_dispatch", "Track state, bucket selector and a joint XOR-mask token; recompute and validate their relationship before business routing, using actual runtime barrier results."},
    {"cfg.bogus_edges", "Add contradictory condition paths into a separate keyed dead-state graph; dead edges never re-enter business domains and therefore cannot poison live register types."},
    {"cfg.loop_state_machine", "Route eligible method CFG backedges through encoded state transitions and dispatch; preserve original conditional, exception and loop-exit behavior."},
    {"cfg.condition_expansion", "Repeat the original branch predicate in budget-aware equivalent guards; preserve operand semantics and true/false destinations, including null and floating comparisons."},
    {"cfg.conditional_nesting", "Wrap selected conditions in layered equivalent guard branches with typed dead alternatives; expansion counts are bounded by full-method encoding budgets."},
    {"cfg.table_dispatch", "Use DEX packed-switch or sparse-switch payloads with relocated signed case offsets; payload alignment and branch references verified after layout."},
    {"cfg.indirect_dispatch", "Replace direct eligible transfers with encoded integer state assignment and typed switch routing, rather than native computed jumps or function pointers."},
    {"cfg.mixed_ps_ss_if", "Combine packed-switch entry routing, sparse-switch typed/bucket dispatch and conditional token checks in one method; legal DEX payloads only."},
    {"cfg.exception_dispatch", "Add isolated synthetic throw/catch routes in dead or prefix regions with move-exception handlers; do not catch or change exceptions from the original business body."},
    {"cfg.callback_style", "Call a generated ()I helper and validate its returned predicate before typed state transitions; interprocedural indirection, not an asynchronous OS callback."},
    {"cfg.tail_recursion", "Convert supported bounded loop shapes to a depth-controlled helper/wrapper recursion protocol; require compatible parameter/register layout, no unsafe try regions and configured call-depth budget."},
    {"cfg.dead_blocks", "Generate seeded acyclic dead-state graphs with arithmetic-keyed edges, local decode islands, sharded switch tables and generated-call-dependent alternate edges; invalid states terminate in a throw."},
    {"cfg.block_reordering", "Seeded physical permutation of business blocks with relocated branches/payloads; methods with unsupported non-CFF debug/try relocation remain unchanged."},
    {"predicate.number_theory", "Runtime Fermat identity: a^30 mod 31 = 1 for a in 1..30; generated arithmetic helper feeds opaque guards."},
    {"predicate.polynomial", "Evaluate both sides of the expanded (x+1)^4 polynomial identity with Java int wraparound modulo 2^32."},
    {"predicate.matrix", "Evaluate determinant 1 of the runtime triangular matrix [[1,2*x],[0,1]]; arithmetic feeds a known invariant guard."},
    {"predicate.bitwise", "Sixteen seeded XOR/add rounds followed by inverse subtract/XOR rounds; compare recovered runtime integer with its initial value."},
    {"predicate.floating_point", "Use DEX cmpl-float NaN comparison behavior (NaN versus finite -> -1) to construct a deterministic runtime predicate."},
    {"predicate.hash_collision", "Java String hashCode polynomial-31 collision for FB and Ea supplies equal hashes for unequal literals."},
    {"predicate.cross_process", "Historical ID: generated cross-PROCEDURE helper state and comparisons; does NOT launch, inspect or communicate with another OS process."},
    {"predicate.cross_class_state", "Seeded volatile fields and accesses across generated classes produce runtime state-dependent invariant guards."},
    {"predicate.crypto", "Custom reversible 16-round two-word add/XOR known-pair check; NOT AES, a standardized cipher, or a cryptographic-security guarantee."},
    {"predicate.graph_problem", "Compute a fixed six-edge graph's bitset reachability relation in generated helper code; not a general hard graph-problem solver."},
    {"predicate.class_loading_state", "Use ClassLoader/System.identityHashCode-derived runtime state with an invariant parity relation; not an anti-debug or anti-emulator guarantee."},
    {"predicate.reference_identity", "Load the same const-class twice and compare Class object reference identity; preserve class-resolution semantics."},
    {"predicate.history", "Update a rolling-history state and compare the corresponding algebraic relation; history is process-local generated runtime state."},
    {"predicate.overflow", "Java signed int wraparound identity: adding Integer.MIN_VALUE twice restores the original 32-bit value."},
    {"data.string_encryption", kStringCipher},
    {"data.string_splitting", "Split selected literal UTF-16 units into chunks reconstructed by generated typed runtime helpers; may compose with the documented custom UTF-16 cipher."},
    {"data.constant_splitting", "Encode 32-bit constants as a seeded initial value plus reversible XOR/add signed-16-bit literal steps modulo 2^32; preserve float bits and polymorphic verifier zero/null. Long programs may be outlined with every arithmetic step retained."},
    {"data.array_virtualization", "Rewrite eligible static-array element reads to generated type-specific accessor methods using the original aget variant; not a general bytecode virtual machine."},
    {"data.array_splitting", "Split eligible static arrays at (length+1)>>>1 using System.arraycopy into two typed fields; generated accessor routes an index to the correct half."},
    {"data.reflection_string_encryption", kStringCipher},
    {"data.enum_lowering", "Keep Enum objects and ordinal semantics; selected ordinal equality sites use a synchronized lazy table encoding ordinal*odd_multiplier XOR mask and equivalently encoded comparison constants."},
    {"data.boolean_arithmetic", "Replace eligible boolean constants with equivalent reversible integer arithmetic while retaining DEX verifier boolean/int and zero/null constraints."},
    {"resources.file_rename", "Collision-checked 16-token Unicode/combining ZIP basenames; exact matching ARSC global path-pool rewrite, extensions and .9.png retained. Native, literal and dynamic path contracts are conservatively kept."},
    {"resources.name_rename", "Safe ARSC package key-pool entries become BirchGuard; IDs, type names and user values unchanged. Dynamic resource/reflective APIs, native libraries, overlays and referenced key literals retain original names."},
    {"anti_analysis.debug_info_removal", "Remove DEX debug programs plus source/parameter metadata before and after lowering; mutually exclusive with debug-local noise."},
    {"anti_analysis.annotation_noise", "Add legal build-visibility synthetic annotations containing seeded token/revision values, eight-int shape data and nested route metadata."},
    {"anti_analysis.path_explosion", "Insert runtime opaque splits and dead alternatives with per-method block budgets; configured analysis cost is not a measured solver runtime or security guarantee."},
    {"anti_analysis.ssa_pollution", "Define scratch values on both opaque branch arms and merge them into subsequent arithmetic, creating additional SSA phi/data-dependency structure."},
    {"anti_analysis.constant_barriers", "Pass reconstructed constants through generated typed runtime identity barriers; distinguish int/float/reference uses and preserve required casts or polymorphic null restoration."},
    {"anti_analysis.instruction_patterns", "Emit seeded eight-round mixed two-address XOR/add/mul/sub scratch arithmetic and compatible instruction replacements; retain legal register widths and observable business results."},
    {"anti_analysis.register_shape", "Vary legal move/16 and move/from16 register encodings and scratch transfer shapes without changing parameter word layout or wide-value pairing."},
    {"anti_analysis.legal_exception_layout", "Generate legal isolated exception-dispatch try/catch regions with relocated handlers; original business exception ranges retain their meaning."},
    {"anti_analysis.verifier_safe_overlap_substitute", "Use a sequential legal exception maze instead of overlapping instruction encodings; does NOT emit verifier-invalid bytecode overlaps."},
    {"anti_analysis.decompiler_resilience", "Compose verifier-safe opaque dispatch and exception maze layouts; this is structural complexity, not a guarantee against any named decompiler."},
    {"anti_analysis.legal_overlapping_handlers", "Create multiple legal try regions sharing handler fan-in; handler entry uses move-exception. DEX try intervals themselves remain nonoverlapping."},
    {"anti_analysis.debug_local_noise", "Insert valid StartLocal/StartLocalExtended and EndLocal records only into existing debug programs; cannot be enabled alongside debug stripping."},
    {"anti_analysis.annotation_forgery", "Add legal runtime-visibility synthetic annotation metadata with seeded origin/shape fields; NOT APK certificate/signature forgery."},
    {"anti_analysis.dataflow_pollution", "Seven rounds of seeded XOR/add/mul scratch dependencies, a register transfer and final XOR-literal step; no business value is replaced by an unproven result."},
    {"anti_analysis.pattern_randomization", "Seeded block ordering plus varied const/XOR/add scratch patterns per round; changes instruction signatures while retaining valid dataflow."},
    {"strength.per_method_randomization", "Derive method-specific selections, constants and composable wrapper strategy order from seed plus method identity; eligibility/verification gates still apply."},
    {"strength.build_parameter_randomization", "Derive build-specific effective parameters from configured reproducibility/seed policy; reproducible mode retains deterministic inputs, not fresh randomness on every run."},
    {"strength.anti_automation_profile", "Enforce the full-strength structural floor (1024 configured dead states at maximum), runtime-linked graph diversity and budget gates; never silently disable failing passes."},
    {"strength.analysis_cost_budget", "Translate target_analysis_cost_weeks into structural strategy/budget inputs; NOT a measured time-to-break estimate, benchmark or security guarantee."},
    {"fake.classes", "Generate configured synthetic classes and methods with seeded arithmetic/control flow; generated runtime bodies remain subject to structural/type and full-strength checks."},
    {"fake.calls", "Insert type-compatible calls to generated methods and use results in opaque/dead routing where eligible; call counters are events rather than unique target counts."},
};
}
std::string_view DescribeTechnique(std::string_view id) {
    const auto found = std::find_if(std::begin(kEntries), std::end(kEntries),
        [id](const auto& entry) { return entry.first == id; });
    return found == std::end(kEntries) ? std::string_view{} : found->second;
}
}
