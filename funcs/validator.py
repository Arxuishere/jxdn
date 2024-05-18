import datetime, time
from datetime import datetime
import validation, validators, ipaddress, json
from ipaddress import IPv4Address, IPv4Network

class Validation:

    @staticmethod
    def validate_ip(ip):
        parts = ip.split('.')
        return len(parts) == 4 and all(x.isdigit() for x in parts) and all(0 <= int(x) <= 255 for x in parts) and not ipaddress.ip_address(ip).is_private
    
    @staticmethod
    def validate_port(port, rand=False):
        if rand:
            return port.isdigit() and int(port) >= 0 and int(port) <= 65535
        else:
            return port.isdigit() and int(port) >= 1 and int(port) <= 65535

    @staticmethod
    def validate_time(key, time):
        with open("./data/database.json") as e:
            data = json.load(e)
        return time.isdigit() and int(time) >= 10 and int(time) <= data["keys"][key]["maxTime"]
    
    @staticmethod
    def validate_method(method):
        with open("./data/attacks.json") as e:
            data = json.load(e)
        for x in data:
            if x['methods'] == method:
                return True
            else:
                return False
    
    @staticmethod
    def is_valid_key(key):
        with open("./data/database.json") as e:
            data = json.load(e)
        key_data = data['keys'][key]
        if key in data['keys']:
            if datetime.strptime(key_data['exp'], '%Y-%m-%d') < datetime.now():
                return True
            else:
                return False
        else:
            return False
    
    @staticmethod
    def validate_domain(domain):
        return validators.domain(domain)

    @staticmethod
    def validate_url(url):
        return validators.url(url)
    
    @staticmethod
    def ip_range_blacklist(ip) -> tuple[bool ,str]:
        with open("./data/blacklist.json") as e:
            data = json.load(e)
        list = dict(data["ranges"])
        for (range, name) in list.items():
            try:
                if IPv4Address(ip) in IPv4Network(range):
                    print(ip, range)
                    return True, name
            except Exception:
                continue
        
        return False, None

    @staticmethod
    def ip_list_blacklist(ip):
        with open("./data/blacklist.json") as e:
            data = json.load(e)
        list = data["hosts"]
        if ip in list:
            return True
