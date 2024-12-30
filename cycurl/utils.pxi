import warnings


class CurlWarning(UserWarning, RuntimeWarning):
    pass


def config_warnings(on: bool = False):
    if on:
        warnings.simplefilter("default", category=CurlWarning)
    else:
        warnings.simplefilter("ignore", category=CurlWarning)

