from typing import cast

from click import Parameter

from uvicorn.main import main

def read_deployment() -> str:
    with open("")

if __name__ == "__main__":
    print(dir(main))
    for param in main.params:
        param = cast(Parameter, param)
        print(param.opts)
