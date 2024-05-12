# First stage: Build stage

# Use the Ubuntu Xenial base image (it has glibc version 2.23 which is
# exploitable because its malloc implementation lacks tcache support)
FROM ubuntu:xenial AS builder

# Install gcc compiler
RUN apt-get update && apt-get install -y gcc && apt-get clean

WORKDIR /usr/src/app

COPY main.c .

# Compile the main.c statically
RUN gcc -o main -static main.c

# Second stage: Run stage
FROM scratch

WORKDIR /app

COPY --from=builder /usr/src/app/main ./

COPY password.txt database.db ./

CMD ["./main"]
