from dojo.tools.burp.parser import BurpParser
from dojo.tools.nessus.parser import NessusParser
from dojo.tools.rapid7.parser import Rapid7Parser

# Add any other parsers that should be available

tool_type = [
    'Burp Scan',
    'Nessus Scan', 
    'Rapid7 Scan',
    # Add any other scan types
]

parser_dict = {
    'Burp Scan': BurpParser(),
    'Nessus Scan': NessusParser(),
    'Rapid7 Scan': Rapid7Parser(),
    # Add any other parsers
}

def get_parser(type):
    if type in parser_dict:
        return parser_dict[type]
    raise Exception('Unknown type %s' % type)
