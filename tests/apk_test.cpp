#include "birch/guard/apk.h"
#include "birch/guard/pipeline.h"

#include <cassert>

int main() {
    birch::guard::ZipArchive archive;
    archive.Add({"AndroidManifest.xml", {0x03, 0x00, 0x08, 0x00, 0, 0, 0, 0}, birch::guard::ZipCompression::Stored});
    archive.Add({"resources.arsc", {0x02, 0x00, 0x0c, 0x00, 0, 0, 0, 0}, birch::guard::ZipCompression::Stored});
    bool rejected = false;
    try {
        (void)birch::guard::InspectApk(archive);
    } catch (const std::exception&) {
        rejected = true;
    }
    assert(rejected);

    const auto pipeline = birch::guard::GuardPipeline::FromJson(R"json({
      "scope": {"protect": [{"pattern": "Lcom/example/**;"}]},
      "passes": {"fake.classes": {"enabled": true, "intensity": 0.2}}
    })json");
    rejected = false;
    try {
        pipeline.TransformApk("missing.apk", "out.apk");
    } catch (const std::exception&) {
        rejected = true;
    }
    assert(rejected);
    return 0;
}
