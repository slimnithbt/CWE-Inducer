"""CWE-level scoring shared by every system: labels -> CWE IDs, micro P/R/F1 over CVEs with >=1 specific gold CWE."""
import re
L2CWE = {'SqlInjection':'89','CrossSiteScripting':'79','CrossSiteRequestForgery':'352','CodeInjection':'94','Cwe94':'94',
 'BufferOverflow':'119','OutOfBoundsRead':'125','PathTraversal':'22','UnrestrictedFileUpload':'434','AuthenticationBypass':'287',
 'MissingAuthentication':'306','MissingAuthorization':'862','IncorrectAuthorization':'863','PrivilegeEscalation':'269',
 'InformationDisclosure':'200','DenialOfService':'400','DeserializationOfUntrustedData':'502','UseOfHardcodedCredentials':'798',
 'OpenRedirect':'601'}
PRODUCTS = {'Wordpress','Cisco','Windows','Linux','Microsoft','Apache','Oracle','Nginx','Joomla','Adobe','Chrome','Android','Ios','Php','Java','Python','Javascript'}
def norm(s): return re.sub(r'[^a-z0-9]', '', s.lower())
ALIAS = {'sqlinjection':'SqlInjection','sqli':'SqlInjection','crosssitescripting':'CrossSiteScripting','xss':'CrossSiteScripting',
 'crosssiterequestforgery':'CrossSiteRequestForgery','csrf':'CrossSiteRequestForgery','commandinjection':'Cwe77','oscommandinjection':'Cwe78',
 'codeinjection':'CodeInjection','remotecodeexecution':'Cwe94','codeexecution':'Cwe94','rce':'Cwe94','bufferoverflow':'BufferOverflow',
 'integeroverflow':'Cwe190','useafterfree':'Cwe416','doublefree':'Cwe415','outofboundsread':'OutOfBoundsRead','outofboundswrite':'Cwe787',
 'memorycorruption':'Cwe119','pathtraversal':'PathTraversal','directorytraversal':'PathTraversal','unrestrictedfileupload':'UnrestrictedFileUpload',
 'arbitraryfileupload':'UnrestrictedFileUpload','authenticationbypass':'AuthenticationBypass','missingauthorization':'MissingAuthorization',
 'incorrectauthorization':'IncorrectAuthorization','privilegeescalation':'PrivilegeEscalation','useofhardcodedcredentials':'UseOfHardcodedCredentials',
 'hardcodedcredentials':'UseOfHardcodedCredentials','xmlexternalentity':'Cwe611','xxe':'Cwe611','serversiderequestforgery':'Cwe918','ssrf':'Cwe918',
 'openredirect':'OpenRedirect','deserializationofuntrusteddata':'DeserializationOfUntrustedData','insecuredeserialization':'DeserializationOfUntrustedData',
 'informationdisclosure':'InformationDisclosure','deserialization':'DeserializationOfUntrustedData','denialofservice':'DenialOfService','dos':'DenialOfService','racecondition':'Cwe362',
 'prototypepollution':'Cwe1321','nullpointerdereference':'Cwe476','wordpress':'Wordpress','cisco':'Cisco','windows':'Windows','linux':'Linux',
 'microsoft':'Microsoft','apache':'Apache','oracle':'Oracle'}
def canon(s):
    n = norm(s)
    if n in ALIAS: return ALIAS[n]
    m = re.fullmatch(r'cwe(\d+)', n)
    return 'Cwe' + m.group(1) if m else s
def to_cwe(label):
    c = canon(label)
    if c in L2CWE: return L2CWE[c]
    m = re.fullmatch(r'Cwe(\d+)', c)
    return m.group(1) if m else None   # products / unknown labels -> not a CWE claim
# lenient matching: CWE families (documented in the paper's appendix)
FAMILIES = {
 'memory': {'119','120','121','122','125','787','131','190','191','416','415','476','193','805','824'},
 'injection': {'74','77','78','94','95','917','1336'},
 'access': {'284','285','862','863','639','269','732','276','266','425','280'},
 'auth': {'287','290','306','307','288','1390','620','640','798','259','521'},
 'exposure': {'200','209','532','538','359','201','312','319','668'},
 'path': {'22','23','24','35','36','59','73'},
 'resource': {'400','770','404','401','772','835','674'},
}
FAM = {c: f for f, s in FAMILIES.items() for c in s}
def fam(c): return FAM.get(c, c)
def score(pred, gold, ids, lenient=False):
    tp = fp = fn = 0
    for c in ids:
        g = set(gold[c]); p = {x for x in (to_cwe(l) for l in pred.get(c, [])) if x}
        if lenient: g = {fam(x) for x in g}; p = {fam(x) for x in p}
        tp += len(p & g); fp += len(p - g); fn += len(g - p)
    P = tp / (tp + fp) if tp + fp else 0.0; R = tp / (tp + fn) if tp + fn else 0.0
    return {'tp': tp, 'fp': fp, 'fn': fn, 'p': P, 'r': R, 'f1': 2 * P * R / (P + R) if P + R else 0.0}
