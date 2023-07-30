from fastapi import FastAPI

import uvicorn


def create_app():
    return FastAPI()


if __name__ == "__main__":
    uvicorn.run(
        "main:create_app",
        # factory=True,
        host="127.0.0.1",
        port=5000,
        log_level="debug",
        reload=True,
        use_colors=True,
    )
