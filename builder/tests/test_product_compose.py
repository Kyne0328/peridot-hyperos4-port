from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from peridot_builder.product_compose import apply_product_plan


def write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


class ProductComposeTests(unittest.TestCase):
    def test_apply_reduction_target_config_and_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            donor = root / "donor"
            stock = root / "stock"

            write(donor / "product/data-app/RemoveMe/app.apk", "remove")
            write(donor / "product/app/SogouIME/SogouIME.apk", "keep")
            write(donor / "product/etc/device_features/madrid.xml", "madrid")
            write(donor / "product/etc/displayconfig/madrid.xml", "madrid-display")
            write(
                donor / "product/etc/permissions/privapp-permissions-product.xml",
                """<?xml version="1.0" encoding="utf-8"?>
<permissions>
    <privapp-permissions package="com.xiaomi.gamecenter.sdk.service">
        <permission name="android.permission.READ_PHONE_STATE" />
    </privapp-permissions>
    <privapp-permissions package="com.keep">
        <permission name="android.permission.READ_PHONE_STATE" />
    </privapp-permissions>
</permissions>
""",
            )
            write(
                donor / "config/product_fs_config",
                "\n".join(
                    [
                        "product 0 0 0755",
                        "product/etc 0 0 0755",
                        "product/data-app 0 0 0755",
                        "product/data-app/RemoveMe 0 0 0755",
                        "product/data-app/RemoveMe/app.apk 0 0 0644",
                        "product/app/SogouIME 0 0 0755",
                        "product/app/SogouIME/SogouIME.apk 0 0 0644",
                        "product/etc/device_features 0 0 0755",
                        "product/etc/device_features/madrid.xml 0 0 0644",
                        "product/etc/displayconfig 0 0 0755",
                        "product/etc/displayconfig/madrid.xml 0 0 0644",
                    ]
                )
                + "\n",
            )
            write(
                donor / "config/product_file_contexts",
                "\n".join(
                    [
                        "/product u:object_r:system_file:s0",
                        "/product/etc u:object_r:system_file:s0",
                        "/product/data-app u:object_r:system_file:s0",
                        "/product/data-app/RemoveMe u:object_r:system_file:s0",
                        "/product/data-app/RemoveMe/app\\.apk u:object_r:system_file:s0",
                        "/product/app/SogouIME u:object_r:system_file:s0",
                        "/product/app/SogouIME/SogouIME\\.apk u:object_r:system_file:s0",
                        "/product/etc/device_features u:object_r:system_file:s0",
                        "/product/etc/device_features/madrid\\.xml u:object_r:system_file:s0",
                        "/product/etc/displayconfig u:object_r:system_file:s0",
                        "/product/etc/displayconfig/madrid\\.xml u:object_r:system_file:s0",
                    ]
                )
                + "\n",
            )

            write(stock / "product/etc/device_features/peridot.xml", "peridot")
            write(stock / "product/etc/displayconfig/peridot-panel.xml", "panel")
            write(
                stock / "config/product_fs_config",
                "\n".join(
                    [
                        "product/etc/device_features 0 0 0755",
                        "product/etc/device_features/peridot.xml 0 0 0644",
                        "product/etc/displayconfig 0 0 0755",
                        "product/etc/displayconfig/peridot-panel.xml 0 0 0644",
                    ]
                )
                + "\n",
            )
            write(
                stock / "config/product_file_contexts",
                "\n".join(
                    [
                        "/product/etc/device_features u:object_r:system_file:s0",
                        "/product/etc/device_features/peridot\\.xml u:object_r:system_file:s0",
                        "/product/etc/displayconfig u:object_r:system_file:s0",
                        "/product/etc/displayconfig/peridot-panel\\.xml u:object_r:system_file:s0",
                    ]
                )
                + "\n",
            )

            reduction = {
                "minimum_reduction_bytes": 1,
                "target_reduction_bytes": 1,
                "approved_reduction_bytes": 10,
                "projected_headroom_after_fit_bytes": 9,
                "safety": {
                    "retained_input_method_package": "com.sogou",
                    "config_cleanup": [],
                },
                "candidates": [
                    {
                        "root": "/data-app/RemoveMe",
                        "package": "com.remove",
                        "on_disk_bytes": 10,
                        "is_input_method": False,
                        "dependencies_reviewed": True,
                        "decision": "approved_remove",
                        "regression_tests": ["boot"],
                    },
                    {
                        "root": "/app/SogouIME",
                        "package": "com.sogou",
                        "on_disk_bytes": 5,
                        "is_input_method": True,
                        "dependencies_reviewed": True,
                        "decision": "retain_required_input_method",
                        "regression_tests": ["keyboard"],
                    },
                ],
            }
            blueprint = {
                "product_target_config": [
                    {
                        "source_partition": "donor_product",
                        "source_path": "/etc/device_features/madrid.xml",
                        "operation": "remove",
                    },
                    {
                        "source_partition": "donor_product",
                        "source_path": "/etc/displayconfig/madrid.xml",
                        "operation": "remove",
                    },
                    {
                        "source_partition": "stock_product",
                        "source_path": "/etc/device_features/peridot.xml",
                        "destination_path": "/etc/device_features/peridot.xml",
                        "operation": "copy_stock_version",
                    },
                    {
                        "source_partition": "stock_product",
                        "source_path": "/etc/displayconfig/peridot-panel.xml",
                        "destination_path": "/etc/displayconfig/peridot-panel.xml",
                        "operation": "copy",
                    },
                ],
                "product_config_cleanup": [
                    {
                        "path": "/etc/permissions/privapp-permissions-product.xml",
                        "operation": "remove_privapp_block",
                        "package": "com.xiaomi.gamecenter.sdk.service",
                    }
                ],
            }

            result = apply_product_plan(
                donor_extract_root=donor,
                stock_extract_root=stock,
                blueprint=blueprint,
                reduction_plan=reduction,
            )

            self.assertFalse((donor / "product/data-app/RemoveMe").exists())
            self.assertTrue((donor / "product/app/SogouIME/SogouIME.apk").is_file())
            self.assertFalse((donor / "product/etc/device_features/madrid.xml").exists())
            self.assertEqual(
                (donor / "product/etc/device_features/peridot.xml").read_text(),
                "peridot",
            )
            permissions = (
                donor / "product/etc/permissions/privapp-permissions-product.xml"
            ).read_text()
            self.assertNotIn("com.xiaomi.gamecenter.sdk.service", permissions)
            self.assertIn("com.keep", permissions)

            fs_config = (donor / "config/product_fs_config").read_text()
            contexts = (donor / "config/product_file_contexts").read_text()
            self.assertNotIn("RemoveMe", fs_config)
            self.assertNotIn("RemoveMe", contexts)
            self.assertNotIn("madrid.xml", fs_config)
            self.assertNotIn("madrid\\.xml", contexts)
            self.assertIn("product 0 0 0755", fs_config)
            self.assertIn("product/etc 0 0 0755", fs_config)
            self.assertIn("/product u:object_r:system_file:s0", contexts)
            self.assertIn("/product/etc u:object_r:system_file:s0", contexts)
            self.assertIn("peridot.xml", fs_config)
            self.assertIn("peridot\\.xml", contexts)
            self.assertEqual(result["cleaned_privapp_packages"], ["com.xiaomi.gamecenter.sdk.service"])


if __name__ == "__main__":
    unittest.main()
