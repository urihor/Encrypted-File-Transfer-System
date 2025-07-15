from server import Server


def main():
    try:
        serv = Server()
        serv.serve()

    except Exception as error:
        print("Exception: ", error)


if __name__ == "__main__":
    main()
