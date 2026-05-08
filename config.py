import os

basedir = os.path.abspath(os.path.dirname(__file__))

class Config(object):
    # Flask
    SECRET_KEY = os.environ["SECRET_KEY"]

    # ========== Azure Blob Storage ==========
    BLOB_ACCOUNT = os.environ["BLOB_ACCOUNT"]
    BLOB_STORAGE_KEY = os.environ["BLOB_STORAGE_KEY"]
    BLOB_CONTAINER = os.environ["BLOB_CONTAINER"]

    # ========== Azure SQL Database ==========
    SQL_SERVER = os.environ["SQL_SERVER"]             
    SQL_DATABASE = os.environ["SQL_DATABASE"]          
    SQL_USER_NAME = os.environ["SQL_USER_NAME"]
    SQL_PASSWORD = os.environ["SQL_PASSWORD"]

    SQLALCHEMY_DATABASE_URI = (
        f"mssql+pyodbc://{SQL_USER_NAME}:{SQL_PASSWORD}"
        f"@{SQL_SERVER}:1433/{SQL_DATABASE}"
        "?driver=ODBC+Driver+17+for+SQL+Server"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # ========== Microsoft OAuth (MSAL) ==========
    CLIENT_ID = os.environ["CLIENT_ID"]               
    CLIENT_SECRET = os.environ["CLIENT_SECRET"]
    TENANT_ID = os.environ["TENANT_ID"]                

    AUTHORITY = f"https://login.microsoftonline.com/{TENANT_ID}"
    REDIRECT_PATH = "/auth"

    SCOPE = ["User.Read"]
    SESSION_TYPE = "filesystem"
    