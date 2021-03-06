from dotenv.main import load_dotenv
from pathlib import Path
from src.app import app

import os

path_env = Path('.') / '.env'
load_dotenv(dotenv_path=path_env)

if __name__ == '__main__':
    # if os.environ['APP'] == 'production':
    app.run(
        host="0.0.0.0",
        port=int(os.environ['PORT']),
        debug=False,
        access_log=False,
        auto_reload=True,
        workers=int("1")
    )

    # elif os.environ['APP'] == 'development':
    #     app.run(
    #         host=os.environ['APP_HOST'],
    #         port=int(os.environ['APP_PORT']),
    #         debug=False if os.environ['APP_DEBUG'] == 'false' else True,
    #         access_log=False if os.environ['APP_DEBUG'] == 'false' else True,
    #         workers=int(os.environ['APP_WORKERS']),
    #         auto_reload=True
    #     )
