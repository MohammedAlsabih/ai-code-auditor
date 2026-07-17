IMPORT_TO_DIST = {
    "cv2": "opencv-python", "PIL": "pillow", "yaml": "pyyaml", "sklearn": "scikit-learn",
    "bs4": "beautifulsoup4", "dotenv": "python-dotenv", "dateutil": "python-dateutil",
    "jwt": "pyjwt", "git": "gitpython", "magic": "python-magic", "Crypto": "pycryptodome",
    "OpenSSL": "pyopenssl", "serial": "pyserial", "docx": "python-docx",
    "pptx": "python-pptx", "fitz": "pymupdf", "nacl": "pynacl", "github": "pygithub",
    "telegram": "python-telegram-bot", "socks": "pysocks", "websocket": "websocket-client",
    "zmq": "pyzmq", "attr": "attrs", "gi": "pygobject",
    "Bio": "biopython", "dns": "dnspython", "grpc": "grpcio",
    "rest_framework": "djangorestframework",
    "psycopg2": "psycopg2-binary", "MySQLdb": "mysqlclient", "kafka": "kafka-python",
    "usb": "pyusb", "snap7": "python-snap7", "ldap": "python-ldap",
    "jose": "python-jose", "memcache": "python-memcached", "openid": "python-openid",
    # well-known import != distribution divergences (a red H008 here would be a
    # false hallucination; these resolve to their real declaring distribution)
    "pkg_resources": "setuptools", "setuptools": "setuptools",
    "OpenGL": "pyopengl", "cairo": "pycairo", "mpl_toolkits": "matplotlib",
    "win32api": "pywin32", "win32com": "pywin32", "pythoncom": "pywin32",
    "win32con": "pywin32", "win32file": "pywin32", "win32event": "pywin32",
    "win32service": "pywin32", "win32serviceutil": "pywin32", "pywintypes": "pywin32",
}
