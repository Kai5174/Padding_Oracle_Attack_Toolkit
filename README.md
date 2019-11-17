# Padding_Oracle_Attack_Toolkit
Padding Oracle Attack (POA) on CBC_MODE, which can encrypt any message that you want.

# How to use

- `poa.py` is the main function to create ciphertext.

```shell
python poa.py
```

- `VulServer.py` is a POA vulnerable server.

```shell
python VulServer.py
```

# How to apply it into your application

## Code Structure
`poa.py` contains two classes `POACommunication` and `POAAnyEncrypt`. You can override corresponding method to make it work in different applications.
