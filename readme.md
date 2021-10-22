# Neoapp

Simple functions for checking JWT tokens and extracting attributes.

Usage for Flask:

```
from flask import Flask, request

app = Flask(__name__, instance_relative_config=True)
app.config.from_pyfile('config.py')

# app.config is just a dict
neo = Neoapp(app.config)

# You can design your helper function, like

def _get_userid_and_locale() -> Tuple[Optional[str], Optional[str]]:
    """
    Returns user identifier (sub) and locale from access token
    """
    token_values = neo.from_authorization_header(request.headers)
    return token_values.get('sub'), token_values.get('locale')

# Usage in handler is like:

@app.route('/handler', methods=['GET'])
def handler_function():
    user_id, locale = _get_userid_and_locale()
    if not user_id:
        return '', 401
    return f'hello {user_id}', 200
```

### Necessary values for neoapp config (config.py)

```
# accept token issuers
ALLOWED_ISSUERS = [
    # 'http://localhost/auth/realms/your_realm',
    'https://your.keycloak.server/auth/realms/your_realm'
]
CHECK_SIGNATURE = True
VERIFY_EXP = True
VERIFY_AUD = True
AUD = 'account'
CERT_EXPIRATION = 3600 * 3  # 3 hours
```

or, if you don't want to use config.py, just pass values as a dict:

```
config = {
    'ALLOWED_ISSUERS' : ['https://your.keycloak.server/auth/realms/your_realm'],
    ...
}
neo = Neoapp(config)
```