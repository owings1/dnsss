if __name__ == '__main__':
    import logging
    logging.basicConfig(level=logging.INFO)
    from .cli import DevCommand
    DevCommand.main()
