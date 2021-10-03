def coro():
    x = int()
    x = yield x
    yield x
    x = yield x
    yield x

c = coro()
print(c.send(None))
print(c.send(3))
print(c.send(None))
print(c)

