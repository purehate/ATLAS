"""
Enhanced extraction utilities for better actor and industry detection
Uses improved patterns and context-aware extraction
"""
import re
from typing import List, Dict, Set
from app.utils.logging import setup_logging

logger = setup_logging()

# Comprehensive actor patterns
ACTOR_PATTERNS = [
    # APT groups
    r'\bAPT\s*-?\s*\d+\b',
    r'\bAdvanced\s+Persistent\s+Threat\s+\d+\b',
    
    # UNC groups (Mandiant naming)
    r'\bUNC\d+\b',
    
    # DEV groups (Microsoft naming)
    r'\bDEV-\d+\b',
    
    # FIN groups (financial crime)
    r'\bFIN\d+\b',
    
    # Common APT names
    r'\bLazarus\s+Group\b',
    r'\bFancy\s+Bear\b',
    r'\bCozy\s+Bear\b',
    r'\bSofacy\b',
    r'\bThe\s+Dukes\b',
    r'\bCarbanak\b',
    r'\bBlackEnergy\b',
    r'\bCobalt\b',
    r'\bDragonfly\b',
    r'\bEnergetic\s+Bear\b',
    r'\bEquation\s+Group\b',
    r'\bGamaredon\b',
    r'\bKimsuky\b',
    r'\bMuddyWater\b',
    r'\bOilRig\b',
    r'\bSandworm\b',
    r'\bStuxnet\b',
    r'\bTurla\b',
    r'\bWizard\s+Spider\b',
    r'\bScattered\s+Spider\b',
    r'\bVice\s+Society\b',
    r'\bALPHV\b',
    r'\bBlackCat\b',
    r'\bLockBit\b',
    r'\bNobelium\b',
    
    # Ransomware groups
    r'\b[A-Z][a-z]+\s+ransomware\b',
    r'\b[A-Z][a-z]+\s+gang\b',
    
    # Context-based patterns
    r'(?:attributed\s+to|linked\s+to|associated\s+with|tracked\s+as)\s+([A-Z][A-Za-z0-9\s-]+)',
    r'(?:threat\s+actor|actor|group)\s+(?:known\s+as|named|called)\s+([A-Z][A-Za-z0-9\s-]+)',
]

# Industry keywords with context
INDUSTRY_KEYWORDS = {
    "financial": {
        "keywords": ["bank", "financial", "finance", "credit", "mortgage", "investment", "trading", 
                     "banking", "credit union", "investment firm", "hedge fund", "trading floor"],
        "context": ["targeting", "attacked", "breached", "compromised", "victim"]
    },
    "healthcare": {
        "keywords": ["hospital", "healthcare", "medical", "pharmaceutical", "pharma", "clinic",
                     "health system", "medical center", "health insurance"],
        "context": ["targeting", "attacked", "breached", "compromised", "victim"]
    },
    "energy": {
        "keywords": ["energy", "power", "utility", "electric", "oil", "gas", "petroleum",
                     "power grid", "energy sector", "utility company"],
        "context": ["targeting", "attacked", "breached", "compromised", "victim"]
    },
    "technology": {
        "keywords": ["technology", "software", "tech", "IT", "cloud", "saas", "platform",
                     "tech company", "software company", "IT services"],
        "context": ["targeting", "attacked", "breached", "compromised", "victim"]
    },
    "government": {
        "keywords": ["government", "federal", "state", "defense", "military", "municipal",
                     "government agency", "federal agency", "defense contractor"],
        "context": ["targeting", "attacked", "breached", "compromised", "victim"]
    },
    "manufacturing": {
        "keywords": ["manufacturing", "factory", "production", "industrial", "manufacturer"],
        "context": ["targeting", "attacked", "breached", "compromised", "victim"]
    },
    "retail": {
        "keywords": ["retail", "store", "commerce", "e-commerce", "retailer", "shopping"],
        "context": ["targeting", "attacked", "breached", "compromised", "victim"]
    },
    "education": {
        "keywords": ["education", "university", "school", "college", "academic", "educational"],
        "context": ["targeting", "attacked", "breached", "compromised", "victim"]
    },
    "transportation": {
        "keywords": ["transportation", "logistics", "shipping", "aviation", "airline", "transport"],
        "context": ["targeting", "attacked", "breached", "compromised", "victim"]
    },
}


def extract_actors_enhanced(text: str, title: str = "", context_window: int = 200) -> List[str]:
    """
    Enhanced actor extraction with better pattern matching and context awareness
    """
    combined_text = f"{title} {text}"
    actors = []
    seen = set()
    
    # Known actor names (case-insensitive matching) - expanded list
    known_actors = [
        # APT Groups
        "APT1", "APT2", "APT3", "APT4", "APT5", "APT6", "APT7", "APT8", "APT9", "APT10",
        "APT11", "APT12", "APT13", "APT14", "APT15", "APT16", "APT17", "APT18", "APT19", "APT20",
        "APT21", "APT22", "APT23", "APT24", "APT25", "APT26", "APT27", "APT28", "APT29", "APT30",
        "APT31", "APT32", "APT33", "APT34", "APT35", "APT36", "APT37", "APT38", "APT39", "APT40", "APT41",
        "APT-C-01", "APT-C-02", "APT-C-03", "APT-C-05", "APT-C-06", "APT-C-07", "APT-C-08", "APT-C-09",
        "APT-C-10", "APT-C-12", "APT-C-15", "APT-C-16", "APT-C-17", "APT-C-19", "APT-C-20", "APT-C-23",
        "APT-C-26", "APT-C-27", "APT-C-28", "APT-C-29", "APT-C-30", "APT-C-32", "APT-C-35", "APT-C-36",
        "APT-C-37", "APT-C-38", "APT-C-39", "APT-C-40", "APT-C-41", "APT-C-42", "APT-C-43", "APT-C-44",
        "APT-C-45", "APT-C-46", "APT-C-47", "APT-C-48", "APT-C-49", "APT-C-50", "APT-C-51", "APT-C-52",
        # Named Groups
        "Lazarus", "Lazarus Group", "HIDDEN COBRA", "Fancy Bear", "Cozy Bear", "Sofacy", "The Dukes",
        "Carbanak", "Anunak", "BlackEnergy", "Cobalt", "Dragonfly", "Energetic Bear", "Equation Group",
        "Gamaredon", "Gorgon Group", "Kimsuky", "MuddyWater", "OilRig", "Panda", "Putter Panda",
        "Sandworm", "Silence", "Stuxnet", "Turla", "WannaCry", "Wizard Spider", "Zeus",
        "FIN7", "FIN8", "FIN9", "FIN10", "FIN11", "FIN12",
        # Mandiant UNC Groups
        "UNC2452", "UNC1878", "UNC1151", "UNC2447", "UNC3004", "UNC3524", "UNC3944", "UNC4034",
        "UNC2891", "UNC2198", "UNC2165", "UNC2158", "UNC2153", "UNC2145", "UNC2140", "UNC2134",
        "UNC2128", "UNC2127", "UNC2124", "UNC2123", "UNC2113", "UNC2109", "UNC2107", "UNC2103",
        # Microsoft DEV Groups
        "Nobelium", "DEV-0537", "DEV-0243", "DEV-0193", "DEV-0133", "DEV-0113", "DEV-0101",
        "DEV-0536", "DEV-0535", "DEV-0534", "DEV-0533", "DEV-0532", "DEV-0531", "DEV-0530",
        "Storm-0558", "Storm-1374", "Storm-1674", "Storm-1811", "Storm-1849", "Storm-0920",
        "Storm-0550", "Storm-0328", "Storm-0252", "Storm-0069", "Storm-0044", "Storm-0028",
        # Ransomware Groups
        "Scattered Spider", "Vice Society", "ALPHV", "BlackCat", "LockBit", "REvil", "Conti",
        "Ryuk", "Maze", "DoppelPaymer", "DarkSide", "BlackMatter", "Hive", "Ragnar Locker",
        "Avaddon", "Egregor", "Sodinokibi", "GandCrab", "SamSam", "WannaCry", "NotPetya",
        # Other Groups
        "RedVDS", "Reaper", "Winnti", "DarkHotel", "Charming Kitten", "Phosphorus", "Chafer",
        "Helix Kitten", "Elfin", "OceanLotus", "Zirconium", "Naikon", "Emissary Panda",
        "Ke3chang", "Operation Cleaver", "Cleaver", "Wocao", "PittyTiger", "Codoso",
        "Dynamite Panda", "Deputy Dog", "Axiom", "Mirage", "Comment Crew", "LuckyMouse",
        "Numbered Panda", "Winnti Group", "Ghostwriter", "SolarWinds",
        # Additional aliases
        "BlueNoroff", "LAPSUS$", "Lapsus", "Karakurt", "BlackByte", "Hive", "BlackBasta",
        "Quantum", "Royal", "Play", "Akira", "8Base", "Ransomed", "Ransomed.vc",
    ]
    
    text_lower = combined_text.lower()
    for actor in known_actors:
        if actor.lower() in text_lower:
            if actor not in seen:
                seen.add(actor)
                actors.append(actor)
    
    # Pattern-based extraction
    for pattern in ACTOR_PATTERNS:
        matches = re.finditer(pattern, combined_text, re.IGNORECASE)
        for match in matches:
            actor = match.group(0).strip()
            # Clean up common prefixes/suffixes
            actor = re.sub(r'^(the|a|an)\s+', '', actor, flags=re.IGNORECASE)
            if len(actor) > 2 and actor not in seen:
                seen.add(actor)
                actors.append(actor)
    
    # Context-based extraction (look for "attributed to X" patterns) - more conservative
    context_patterns = [
        r'(?:attributed\s+to|linked\s+to|associated\s+with|tracked\s+as|known\s+as)\s+([A-Z][A-Za-z0-9-]{2,20}(?:\s+[A-Z][A-Za-z0-9-]{0,10})?)',
    ]
    
    for pattern in context_patterns:
        matches = re.finditer(pattern, combined_text, re.IGNORECASE)
        for match in matches:
            if match.lastindex:
                actor = match.group(1).strip()
                # Filter out common false positives and long phrases
                if actor and 2 < len(actor) < 30:
                    actor_lower = actor.lower()
                    if actor_lower not in ['the', 'a', 'an', 'this', 'that', 'attacks', 'organizations']:
                        # Check if it looks like an actor name (starts with capital, no common words)
                        if not any(word in actor_lower for word in ['on', 'and', 'or', 'the', 'a', 'an']):
                            if actor not in seen:
                                seen.add(actor)
                                actors.append(actor)
    
    return actors[:15]  # Limit to 15 per document


def extract_industries_enhanced(text: str, title: str = "") -> List[str]:
    """
    Enhanced industry extraction with context awareness
    """
    combined_text = f"{title} {text}".lower()
    found_industries = []
    
    for industry, data in INDUSTRY_KEYWORDS.items():
        keywords = data["keywords"]
        context_words = data["context"]
        
        # Check if any keywords appear
        keyword_found = any(keyword in combined_text for keyword in keywords)
        
        # If keyword found, check for context (optional but improves accuracy)
        if keyword_found:
            # Look for context within 50 chars of keyword
            for keyword in keywords:
                if keyword in combined_text:
                    # Check for context nearby
                    keyword_pos = combined_text.find(keyword)
                    context_window = combined_text[max(0, keyword_pos-50):keyword_pos+50]
                    if any(ctx in context_window for ctx in context_words):
                        if industry not in found_industries:
                            found_industries.append(industry)
                        break
    
    return found_industries


def extract_techniques_enhanced(text: str) -> List[str]:
    """
    Enhanced technique extraction - finds MITRE IDs (including sub-techniques) and maps descriptions
    Prioritizes sub-techniques over parent techniques for granularity
    """
    techniques = []
    parent_techniques = set()  # Track parent techniques to avoid duplicates
    
    # Standard MITRE ID pattern (matches both parent and sub-techniques)
    # Pattern: T#### or T####.###
    mitre_pattern = r'\bT\d{4}(?:\.\d{3})?\b'
    matches = re.finditer(mitre_pattern, text, re.IGNORECASE)
    for match in matches:
        tech_id = match.group(0).upper()
        
        # If it's a sub-technique, add it
        if '.' in tech_id:
            if tech_id not in techniques:
                techniques.append(tech_id)
                # Track parent to avoid adding it later
                parent_techniques.add(tech_id.split('.')[0])
        else:
            # It's a parent technique - only add if we haven't seen a sub-technique for it
            if tech_id not in parent_techniques and tech_id not in techniques:
                techniques.append(tech_id)
    
    # Map common attack descriptions to techniques (expanded with sub-techniques for granularity)
    technique_mappings = {
        # Initial Access
        "phishing": ["T1566.001", "T1566.002", "T1566.003"],  # Spearphishing Link, Attachment, Service
        "spearphishing": ["T1566.001", "T1566.002"],
        "spear phishing": ["T1566.001", "T1566.002"],
        "spearphishing link": ["T1566.002"],
        "spearphishing attachment": ["T1566.001"],
        "spearphishing service": ["T1566.003"],
        "email phishing": ["T1566.001", "T1566.002"],
        "malicious link": ["T1566.002"],
        "malicious attachment": ["T1566.001"],
        "drive-by compromise": ["T1189"],
        "exploit public-facing application": ["T1190"],
        "external remote services": ["T1133"],
        "supply chain compromise": ["T1195.001", "T1195.002", "T1195.003"],  # Compromise Software Dependencies, Development Tools, Software Supply Chain
        "trusted relationship": ["T1199"],
        "valid accounts": ["T1078.001", "T1078.002", "T1078.003", "T1078.004"],  # Default, Domain, Local, Cloud
        "default accounts": ["T1078.001"],
        "domain accounts": ["T1078.002"],
        "local accounts": ["T1078.003"],
        "cloud accounts": ["T1078.004"],
        
        # Execution
        "command and scripting interpreter": ["T1059.001", "T1059.003", "T1059.005", "T1059.006", "T1059.007"],  # PowerShell, Windows CMD, Unix Shell, Python, JavaScript
        "powershell": ["T1059.001"],
        "cmd": ["T1059.003"],
        "windows command shell": ["T1059.003"],
        "unix shell": ["T1059.005"],
        "python": ["T1059.006"],
        "javascript": ["T1059.007"],
        "jscript": ["T1059.007"],
        "vbscript": ["T1059.005"],
        "user execution": ["T1204.001", "T1204.002"],  # Malicious File, Malicious Link
        "scheduled task": ["T1053.005", "T1053.006"],  # Scheduled Task, Systemd Timers
        "scheduled task/job": ["T1053.005", "T1053.006"],
        "service execution": ["T1569.001", "T1569.002"],  # System Services, Service Execution
        "windows management instrumentation": ["T1047"],
        "windows service": ["T1569.002"],
        
        # Persistence
        "boot or logon autostart execution": ["T1547.001", "T1547.002", "T1547.003", "T1547.004", "T1547.005"],  # Boot or Logon Autostart Execution sub-techniques
        "bootkit": ["T1547.001"],
        "autostart execution": ["T1547.001"],
        "scheduled task/job": ["T1053.005", "T1053.006"],
        "boot or logon initialization scripts": ["T1037.001", "T1037.002", "T1037.003", "T1037.004", "T1037.005"],  # Boot/Logon Initialization Scripts
        "create or modify system process": ["T1543.001", "T1543.002", "T1543.003", "T1543.004"],  # Launch Agent, Systemd Service, Windows Service, Launch Daemon
        "event triggered execution": ["T1546.001", "T1546.002", "T1546.003", "T1546.004", "T1546.005", "T1546.006", "T1546.007", "T1546.008", "T1546.009", "T1546.010", "T1546.011", "T1546.012", "T1546.013", "T1546.014", "T1546.015"],  # Change Default File Association, Screensaver, Windows Management Instrumentation Event Subscription, etc.
        "hijack execution flow": ["T1574.001", "T1574.002", "T1574.004", "T1574.005", "T1574.006", "T1574.007", "T1574.008", "T1574.009", "T1574.010", "T1574.011", "T1574.012"],  # DLL Search Order Hijacking, DLL Side-Loading, etc.
        "create account": ["T1136.001", "T1136.002", "T1136.003"],  # Local, Domain, Cloud
        "modify authentication process": ["T1556.001", "T1556.002", "T1556.003", "T1556.004", "T1556.005", "T1556.006", "T1556.007"],  # Domain Controller Authentication, Password Filter DLL, Pluggable Authentication Modules, etc.
        
        # Privilege Escalation
        "privilege escalation": ["T1068"],
        "exploitation for privilege escalation": ["T1068"],
        "abuse elevation control mechanism": ["T1548.001", "T1548.002", "T1548.003", "T1548.004"],  # Setuid and Setgid, Bypass User Account Control, Sudo and Sudo Caching, Elevated Execution with Prompt
        "uac bypass": ["T1548.002"],
        "sudo": ["T1548.003"],
        "access token manipulation": ["T1134.001", "T1134.002", "T1134.003", "T1134.004", "T1134.005"],  # Token Impersonation/Theft, Create Process with Token, Make and Impersonate Token, Parent PID Spoofing, SID-History Injection
        "token impersonation": ["T1134.001"],
        "token theft": ["T1134.001"],
        "process injection": ["T1055.001", "T1055.002", "T1055.003", "T1055.004", "T1055.005", "T1055.008", "T1055.009", "T1055.011", "T1055.012", "T1055.013", "T1055.014", "T1055.015"],  # Dynamic-link Library Injection, Portable Executable Injection, Thread Execution Hijacking, Asynchronous Procedure Call, Thread Local Storage, Ptrace System Calls, Proc Memory, Extra Window Memory Injection, Process Doppelgänging, VDSO Hijacking, ListPlanting, etc.
        "dll injection": ["T1055.001"],
        "pe injection": ["T1055.002"],
        "thread hijacking": ["T1055.003"],
        
        # Defense Evasion
        "defense evasion": ["T1562"],
        "disable or modify tools": ["T1562.001"],
        "impair defenses": ["T1562"],
        "indicator removal": ["T1070"],
        "masquerading": ["T1036"],
        "modify registry": ["T1112"],
        "obfuscated files or information": ["T1027"],
        "process injection": ["T1055"],
        "rootkit": ["T1014"],
        "system binary proxy execution": ["T1218"],
        "unused/unsupported cloud regions": ["T1535"],
        
        # Credential Access
        "credential theft": ["T1003.001", "T1003.002", "T1003.003", "T1003.004", "T1003.005", "T1003.006", "T1003.007", "T1003.008", "T1555.001", "T1555.002", "T1555.003", "T1555.004", "T1555.005"],
        "credential access": ["T1110.001", "T1110.002", "T1110.003", "T1110.004"],
        "brute force": ["T1110.001", "T1110.002"],
        "password guessing": ["T1110.001"],
        "password cracking": ["T1110.002"],
        "password spraying": ["T1110.003"],
        "credential stuffing": ["T1110.004"],
        "credential dumping": ["T1003.001", "T1003.002", "T1003.003", "T1003.004", "T1003.005", "T1003.006", "T1003.007", "T1003.008"],
        "lsass memory": ["T1003.001"],
        "sam": ["T1003.002"],
        "ntds": ["T1003.003"],
        "lsa secrets": ["T1003.004"],
        "cached domain credentials": ["T1003.005"],
        "dcc2": ["T1003.006"],
        "proc filesystem": ["T1003.007"],
        "/etc/passwd and /etc/shadow": ["T1003.008"],
        "os credential dumping": ["T1003.001", "T1003.002", "T1003.003", "T1003.004", "T1003.005", "T1003.006", "T1003.007", "T1003.008"],
        "steal or forge kerberos tickets": ["T1558.001", "T1558.002", "T1558.003", "T1558.004"],  # Golden Ticket, Silver Ticket, Kerberoasting, AS-REP Roasting
        "golden ticket": ["T1558.001"],
        "silver ticket": ["T1558.002"],
        "kerberoasting": ["T1558.003"],
        "as-rep roasting": ["T1558.004"],
        "unsecured credentials": ["T1552.001", "T1552.002", "T1552.003", "T1552.004", "T1552.005", "T1552.006", "T1552.007"],
        "keychain": ["T1555.001"],
        "credentials from password stores": ["T1555.001", "T1555.002", "T1555.003", "T1555.004", "T1555.005"],
        "credentials in files": ["T1552.001"],
        "credentials in registry": ["T1552.002"],
        "credentials in cloud": ["T1552.006"],
        
        # Discovery
        "system information discovery": ["T1082"],
        "process discovery": ["T1057"],
        "system network configuration discovery": ["T1018"],
        "system network connections discovery": ["T1049"],
        "remote system discovery": ["T1018"],
        "system owner/user discovery": ["T1033"],
        "network service scanning": ["T1046"],
        "permission groups discovery": ["T1069"],
        
        # Lateral Movement
        "lateral movement": ["T1021.001", "T1021.002", "T1021.003", "T1021.004", "T1021.005", "T1021.006", "T1078.001", "T1078.002", "T1078.003", "T1078.004"],
        "remote services": ["T1021.001", "T1021.002", "T1021.003", "T1021.004", "T1021.005", "T1021.006"],
        "ssh": ["T1021.004"],
        "rdp": ["T1021.001"],
        "remote desktop protocol": ["T1021.001"],
        "smb": ["T1021.002"],
        "windows admin shares": ["T1021.002"],
        "distributed component object model": ["T1021.003"],
        "dcom": ["T1021.003"],
        "vnc": ["T1021.005"],
        "windows remote management": ["T1021.006"],
        "winrm": ["T1021.006"],
        "use alternate authentication material": ["T1550.001", "T1550.002", "T1550.003", "T1550.004", "T1550.005", "T1550.006"],
        "application access token": ["T1550.001"],
        "pass the hash": ["T1550.002"],
        "pass the ticket": ["T1550.003"],
        "web session cookie": ["T1550.004"],
        "pluggable authentication modules": ["T1550.005"],
        "network device authentication": ["T1550.006"],
        
        # Collection
        "data collection": ["T1005"],
        "archive collected data": ["T1560"],
        "clipboard data": ["T1115"],
        "data from local system": ["T1005"],
        "data from network shared drive": ["T1039"],
        "data from removable media": ["T1025"],
        "email collection": ["T1114"],
        "input capture": ["T1056"],
        "screen capture": ["T1113"],
        
        # Command and Control
        "command and control": ["T1071", "T1090"],
        "application layer protocol": ["T1071"],
        "web protocols": ["T1071.001"],
        "dns": ["T1071.004"],
        "data encoding": ["T1132"],
        "non-application layer protocol": ["T1095"],
        "protocol tunneling": ["T1572"],
        "proxy": ["T1090"],
        "web service": ["T1102"],
        "ingress tool transfer": ["T1105"],
        "remote access software": ["T1219"],
        
        # Exfiltration
        "data exfiltration": ["T1041", "T1537.001", "T1537.002"],
        "exfiltration over network": ["T1041"],
        "exfiltration over c2 channel": ["T1041"],
        "exfiltration over web service": ["T1567.001", "T1567.002", "T1567.003"],
        "exfiltration to code repository": ["T1567.001"],
        "exfiltration to cloud storage": ["T1567.002"],
        "exfiltration to text storage sites": ["T1567.003"],
        "automated exfiltration": ["T1020"],
        "transfer data to cloud account": ["T1537.001"],
        "transfer data to cloud storage": ["T1537.002"],
        
        # Impact
        "ransomware": ["T1486"],
        "data encrypted for impact": ["T1486"],
        "data destruction": ["T1485"],
        "endpoint denial of service": ["T1499"],
        "network denial of service": ["T1498"],
        "service stop": ["T1489"],
        "system shutdown/reboot": ["T1529"],
        "inhibit system recovery": ["T1490"],
        "resource hijacking": ["T1496"],
    }
    
    text_lower = text.lower()
    for description, tech_ids in technique_mappings.items():
        if description in text_lower:
            for tech_id in tech_ids:
                if tech_id not in techniques:
                    techniques.append(tech_id)
    
    return techniques
