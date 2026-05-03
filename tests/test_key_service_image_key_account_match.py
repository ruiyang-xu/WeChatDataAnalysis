import asyncio
import sys
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))


import wechat_decrypt_tool.key_service as key_service


class TestKeyServiceImageKeyAccountMatch(unittest.TestCase):
    def test_local_image_keys_do_not_match_by_substring(self) -> None:
        with mock.patch.object(
            key_service,
            "try_get_local_image_keys",
            return_value=[
                {"wxid": "wxid_demo", "xor_key": "0x01", "aes_key": "AAAAAAAAAAAAAAAA"},
            ],
        ), mock.patch.object(
            key_service,
            "_resolve_account_dir",
            return_value=Path("D:/tmp/output/databases/wxid_demo_extra"),
        ), mock.patch.object(
            key_service,
            "_resolve_account_wxid_dir",
            return_value=Path("D:/tmp/xwechat_files/wxid_demo_extra"),
        ), mock.patch.object(
            key_service,
            "upsert_account_keys_in_store",
        ) as upsert_mock:
            with self.assertRaises(RuntimeError):
                asyncio.run(key_service.get_image_key_integrated_workflow("wxid_demo_extra"))

        upsert_mock.assert_not_called()

    def test_local_image_keys_require_exact_account_match(self) -> None:
        with mock.patch.object(
            key_service,
            "try_get_local_image_keys",
            return_value=[
                {"wxid": "wxid_demo", "xor_key": "0x01", "aes_key": "AAAAAAAAAAAAAAAA"},
                {"wxid": "wxid_demo_extra", "xor_key": "0x8A", "aes_key": "BBBBBBBBBBBBBBBB"},
            ],
        ), mock.patch.object(
            key_service,
            "_resolve_account_dir",
            return_value=Path("D:/tmp/output/databases/wxid_demo_extra"),
        ), mock.patch.object(
            key_service,
            "_resolve_account_wxid_dir",
            return_value=Path("D:/tmp/xwechat_files/wxid_demo_extra"),
        ), mock.patch.object(
            key_service,
            "upsert_account_keys_in_store",
        ) as upsert_mock:
            result = asyncio.run(key_service.get_image_key_integrated_workflow("wxid_demo_extra"))

        self.assertEqual(result["wxid"], "wxid_demo_extra")
        self.assertEqual(result["xor_key"], "0x8A")
        self.assertEqual(result["aes_key"], "BBBBBBBBBBBBBBBB")
        upsert_mock.assert_called_once_with(
            account="wxid_demo_extra",
            image_xor_key="0x8A",
            image_aes_key="BBBBBBBBBBBBBBBB",
        )

    def test_remote_key_fetch_is_disabled(self) -> None:
        """Remote key extraction must be permanently refused (no network call)."""
        with self.assertRaises(RuntimeError):
            asyncio.run(
                key_service.fetch_and_save_remote_keys(
                    "wxid_v4mbduwqtzpt22",
                    db_storage_path="/tmp/does/not/matter",
                )
            )


if __name__ == "__main__":
    unittest.main()
