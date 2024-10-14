<h1> Instructions for Trudy1 </h1>

<h2>🛠️ Execution Steps:</h2>

<p>1. Perform DNS spoofing to involve Trudy1 as the Man-In-The-Middle using the command:</p>

```shell
bash ~/poison-dns-alice1-bob1.sh
```

<p>2. Login into the Trudy1 from one terminal using the command:</p>

```shell
lxc exec trudy1 bash
```

<p>3a. To eavesdrop a chat session between Alice1 and Bob1, compile the program using the command:</p>

```shell
gcc secure_chat_interceptor.c -o secure_chat_interceptor -lssl -lcrypto
```

<p>3b. To tamper with a chat session between Alice1 and Bob1, compile the program using the command:</p>

```shell
gcc secure_chat_active_interceptor.c -o secure_chat_active_interceptor -lssl -lcrypto
```

<p>4a. Run the eavesdrop attack program before client program using the command:</p>

```shell
./secure_chat_interceptor -d alice1 bob1
```

<p>4b. Run the MITM attack program before client program using the command:</p>

```shell
./secure_chat_active_interceptor -m alice1 bob1
```

<p>5. End the chat session (in MITM attack) using the message:</p>

```shell
exit
```

<p>6. Restore the DNS table with original IP addresses using the command:</p>

```shell
bash ~/unpoison-dns-alice1-bob1.sh
```