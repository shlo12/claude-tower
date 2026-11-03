"""UA 里的国产浏览器 / 国产设备特征。

这一项补的是「语言和时区都改了，但浏览器本身还是国产的」那种漏。
判据全是纯函数，不联网、不读文件，所以可以逐条钉死。
"""
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from core import browserwebrtc, scanner, uatraits  # noqa: E402

WECHAT = ("Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) "
          "AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 "
          "MicroMessenger/8.0.47(0x18002f2c) NetType/WIFI Language/zh_CN")
CHROME_MAC = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
              "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")
HARMONY_QUARK = ("Mozilla/5.0 (Linux; Android 12; HarmonyOS; NOH-AN00) "
                 "AppleWebKit/537.36 (KHTML, like Gecko) Quark/6.9.0.360 Mobile Safari/537.36")
XIAOMI = ("Mozilla/5.0 (Linux; Android 13; 2211133C) AppleWebKit/537.36 "
          "(KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36")
VIVALDI = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
           "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Vivaldi/6.5")


class BrowserTests(unittest.TestCase):
    def test_wechat_is_detected(self):
        self.assertEqual(uatraits.classify_browser(WECHAT), "微信 / 企业微信")

    def test_plain_chrome_is_clean(self):
        self.assertEqual(uatraits.classify_browser(CHROME_MAC), "")

    def test_quark_is_detected(self):
        self.assertEqual(uatraits.classify_browser(HARMONY_QUARK), "夸克")

    def test_matching_is_case_insensitive(self):
        self.assertEqual(uatraits.classify_browser(WECHAT.lower()), "微信 / 企业微信")

    def test_vivaldi_is_not_a_chinese_browser(self):
        # `/mi/` 会匹配 "Mozilla"，这种过宽的正则会让每台机器都命中。
        self.assertEqual(uatraits.classify_browser(VIVALDI), "")

    def test_empty_ua_is_not_a_hit(self):
        self.assertEqual(uatraits.classify_browser(""), "")


class DeviceTests(unittest.TestCase):
    def test_harmonyos_is_conclusive(self):
        name, score = uatraits.classify_device(HARMONY_QUARK)
        self.assertEqual(name, "鸿蒙")
        self.assertEqual(score, 1.0)

    def test_xiaomi_model_codes(self):
        for ua in (XIAOMI,
                   "Mozilla/5.0 (Linux; Android 12; M2101K7AG) AppleWebKit/537.36"):
            self.assertEqual(uatraits.classify_device(ua)[0], "小米 / 红米", ua)

    def test_mac_ua_has_no_device(self):
        self.assertEqual(uatraits.classify_device(CHROME_MAC), ("", 0.0))

    def test_global_brands_score_lower(self):
        _, harmony = uatraits.classify_device(HARMONY_QUARK)
        _, xiaomi = uatraits.classify_device(XIAOMI)
        self.assertGreater(harmony, xiaomi)


class ClassifyTests(unittest.TestCase):
    def test_empty_ua_is_unchecked(self):
        info = uatraits.classify("")
        self.assertFalse(info["checked"])
        self.assertEqual(info["browser"], "")

    def test_both_browser_and_device(self):
        info = uatraits.classify(HARMONY_QUARK)
        self.assertTrue(info["checked"])
        self.assertEqual(info["browser"], "夸克")
        self.assertEqual(info["device"], "鸿蒙")

    def test_ua_is_truncated(self):
        info = uatraits.classify("A" * 5000)
        self.assertLessEqual(len(info["ua"]), uatraits.MAX_UA)

    def test_describe_is_one_line(self):
        text = uatraits.describe(uatraits.classify(HARMONY_QUARK))
        self.assertIn("夸克", text)
        self.assertIn("鸿蒙", text)
        self.assertNotIn("\n", text)


class ScannerItemTests(unittest.TestCase):
    """`_check_browser_ua` 的四条出口。"""

    def with_ua(self, ua):
        orig = browserwebrtc.load
        browserwebrtc.load = lambda: {"ua": ua} if ua is not None else {}
        try:
            return scanner._check_browser_ua()
        finally:
            browserwebrtc.load = orig

    def test_no_probe_is_info_not_pass(self):
        out = self.with_ua(None)
        self.assertEqual(out["id"], "fp.cn_browser")
        self.assertEqual(out["severity"], "info")
        self.assertIn("没测过不代表干净", out["detail"])

    def test_empty_ua_is_also_info(self):
        self.assertEqual(self.with_ua("")["severity"], "info")

    def test_chinese_browser_is_high(self):
        out = self.with_ua(WECHAT)
        self.assertEqual(out["severity"], "high")
        self.assertIn("微信", out["title"])

    def test_harmony_device_is_medium(self):
        out = self.with_ua("Mozilla/5.0 (Linux; Android 12; HarmonyOS; NOH-AN00)")
        self.assertEqual(out["severity"], "medium")
        self.assertIn("鸿蒙", out["title"])

    def test_xiaomi_device_is_low(self):
        out = self.with_ua(XIAOMI)
        self.assertEqual(out["severity"], "low")
        self.assertIn("小米", out["title"])

    def test_clean_ua_passes(self):
        out = self.with_ua(CHROME_MAC)
        self.assertEqual(out["severity"], "pass")

    def test_device_advice_discourages_spoofing(self):
        # 改 UA 但时区/语言/字体对不上，比不改更像刻意伪装，所以建议里要明说别改。
        out = self.with_ua(XIAOMI)
        self.assertIn("不建议", out["advice"])

    def test_browser_advice_points_at_switching_browser(self):
        out = self.with_ua(WECHAT)
        self.assertIn("Chrome", out["advice"])
        self.assertIn("配置档案", out["advice"])


if __name__ == "__main__":
    unittest.main(verbosity=1)
