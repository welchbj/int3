import int3


def main():
    cc = int3.Compiler.from_str("linux/x86_64")

    with cc.try_finally() as (try_, finally_):
        with try_:
            ...
        with finally_:
            ...


if __name__ == "__main__":
    main()
