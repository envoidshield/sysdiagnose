from parsers.powerlogs import parse_path, get_log_files
from tests import SysdiagnoseTestCase
import unittest


class TestParsersPowerlogs(SysdiagnoseTestCase):

    def test_get_powerlogs(self):
        for log_root_path in self.log_root_paths:
            files = get_log_files(log_root_path)
            for file in files:
                print(f'Parsing {file}')
                result = parse_path(file)
                if result:  # some files are empty
                    self.assertTrue('sqlite_sequence' in result)


if __name__ == '__main__':
    unittest.main()
