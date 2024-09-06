#############################################################################
#   Copyright 2024 Aon plc
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
#############################################################################


class AttackState:
    arp_cache = {}
    dns_cache = {}
    authoritative_nameservers = []

    @classmethod
    def get_authoritative_nameservers(self):
        return self.authoritative_nameservers

    @classmethod
    def get_arp_cache(self):
        return self.arp_cache

    @classmethod
    def get_dns_cache(self):
        return self.dns_cache

    @classmethod
    def set_authoritative_nameservers(self, authoritative_nameservers):
        self.authoritative_nameservers = authoritative_nameservers

    @classmethod
    def set_arp_cache(self, key, value):
        self.arp_cache[key] = value

    @classmethod
    def set_dns_cache(self, key, value):
        self.dns_cache[key] = value
