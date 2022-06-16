## TODO: do Azure example (Flask-Appbuilder has a thing that decode the JWT from azure built in)

#######################################
# Custom AirflowSecurityManager
#######################################

from airflow.www.security import AirflowSecurityManager


class CustomSecurityManager(AirflowSecurityManager):
    def get_oauth_user_info(self, provider, resp):
        if provider == "aws_cognito":

            # TODO: Authlib supports decoding the `id_token` automatically
            #

            # TODO: we can retrieve the userInfo from the `id_token` using `oauth.google.userinfo(request)`
            #
            #       (But I think it somehow decodes it into the Authlib UserInfo structure, which wont recognise the "cognito:groups" claim,
            #        ?? unless we extend it)
            #from authlib.jose import JsonWebSignature
            #jws = JsonWebSignature()
            #jws.deserialize()

            # TODO: its probably easier to use discovery URIs for most providers (especailly to know the JWKS key location)
            #       the openid discovery for AWS Cognito is:
            #       https://cognito-idp.[region].amazonaws.com/[userPoolId]/.well-known/openid-configuration

            # TODO: flask appbuilder has some kind of AUTH_OPENID already, but it:
            #       1. dosent use authlib (uses flask-openid)
            #       2. dosent support group binding

            userinfo = self.appbuilder.sm.oauth_remotes[provider].get("userinfo").json()
            return {
                "username": "cognito_" + userinfo.get("sub", ""),
                "first_name": userinfo.get("given_name", ""),
                "last_name": userinfo.get("family_name", ""),
                "email": userinfo.get("email", ""),

                # NOTE: this hard-codes all Cognito users as being a member of "FAB_USERS"
                #       which is mapped in the following `AUTH_ROLES_MAPPING` to "Users",
                #       (there is probably a way to extract group information from cognito itself,
                #        if you know how, please raise a PR for these docs!)
                "role_keys": ["FAB_USERS"],
            }
        else:
            return {}


#######################################
# Actual `webserver_config.py`
#######################################
from flask_appbuilder.security.manager import AUTH_OAUTH

# NOTE: only needed for airflow 1.10
# from airflow import configuration as conf
# SQLALCHEMY_DATABASE_URI = conf.get("core", "SQL_ALCHEMY_CONN")

AUTH_TYPE = AUTH_OAUTH
SECURITY_MANAGER_CLASS = CustomSecurityManager

# registration configs
AUTH_USER_REGISTRATION = True  # allow users who are not already in the FAB DB
AUTH_USER_REGISTRATION_ROLE = "Public"  # this role will be given in addition to any AUTH_ROLES_MAPPING

# the list of providers which the user can choose from
OAUTH_PROVIDERS = [
    {
        "name": "aws_cognito",
        "icon": "fa-amazon",
        "token_key": "access_token",
        "remote_app": {
            "client_id": "COGNITO_CLIENT_ID",
            "client_secret": "COGNITO_CLIENT_SECRET",
            "api_base_url": "https://COGNITO_POOL.auth.AWS_REGION.amazoncognito.com/oauth2/",
            "client_kwargs": {"scope": "openid profile email cognito:groups"},
            "access_token_url": "https://COGNITO_POOL.auth.AWS_REGION.amazoncognito.com/oauth2/authorize",
            "authorize_url": "https://COGNITO_POOL.auth.AWS_REGION.amazoncognito.com/oauth2/token",

            # TODO: what happens when I specify `jwks_uri`,
            #       ?? will there be a UserInfo instance in the "userinfo"
            #          key of the` resp` dict passed to `get_oauth_user_info()`
            #       ?? how can I extend UserInfo so non-standard claims are included
            #          !! it seems that UserInfo is just a dictionary, with a __getattr__ which errors when accessing unexpected keys
            #             (I can probably just
            #       !! these links are useful:
            #          https://github.com/lepture/authlib/blob/master/authlib/integrations/flask_client/apps.py#L108
            #          https://github.com/lepture/authlib/blob/master/authlib/integrations/base_client/sync_openid.py#L32-L77
            #          https://docs.authlib.org/en/latest/client/frameworks.html#parsing-id-token
            #       !! the fact that UserInfo is automatically unpacked from `id_token` means we can
            #          significantly simplify the built-in `get_oauth_user_info()` of Flask-Appbuilder
            #       !! I need to actually test with Okta/GitHub/Cognito to verify that UserInfo is actually returned
            #          (and that it contains any custom claims for that provider)

        },
    },
]

# a mapping from the values of `userinfo["role_keys"]` to a list of FAB roles
AUTH_ROLES_MAPPING = {
    "FAB_USERS": ["User"],
    "FAB_ADMINS": ["Admin"],
}

# if we should replace ALL the user's roles each login, or only on registration
AUTH_ROLES_SYNC_AT_LOGIN = True

# force users to re-auth after 30min of inactivity (to keep roles in sync)
PERMANENT_SESSION_LIFETIME = 1800