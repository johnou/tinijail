# tinijail

small linux seccomp agent that prevents java processes from launching executables.

loads with `-agentpath` and installs a filter denying `execve` and `execveat`. java starts normally, but calls such as `ProcessBuilder.start()` and `Runtime.exec()` fail with `IOException` and `Operation not permitted`.

supports linux x86-64 and arm64. 32-bit architectures are not supported.

## docker

build the agent in a separate stage and copy it into your existing image. this example assumes `guard.c` is in the docker build context and the runtime image is based on amazon linux 2023. use a builder compatible with your runtime image's architecture and libc.

```dockerfile
FROM amazoncorretto:11 AS tinijail-build
RUN dnf install -y gcc && dnf clean all
COPY guard.c /src/guard.c
RUN gcc -O2 -Wall -Wextra -Werror -shared -fPIC \
    -I/usr/lib/jvm/java-11-amazon-corretto/include \
    -I/usr/lib/jvm/java-11-amazon-corretto/include/linux \
    -o /src/tinijail.so /src/guard.c

# replace this with your existing runtime image
FROM amazoncorretto:11
COPY --from=tinijail-build /src/tinijail.so /usr/local/lib/tinijail.so

# add your application and existing configuration here
```

add agent to your existing java command:

```sh
java -agentpath:/usr/local/lib/tinijail.so -jar /app/app.jar
```

tini can launch java as usual. java fails startup if agent cannot load or install filter.

## limitations

- `-XX:OnOutOfMemoryError` cannot run commands. `-XX:+HeapDumpOnOutOfMemoryError` can still write a heap dump; use a separate process or sidecar to process it.
- `kubectl exec` starts a separate process and is not blocked by the java process's filter. restrict it using kubernetes rbac.
- the guard blocks execution of new programs, not `fork` or code running inside the existing process. it is not a complete sandbox.
- the kernel and container seccomp policy must allow installing another filter. java fails startup if installation fails.
- agent must be configured in every java process that needs protection.

## status

proof of concept. tested locally on arm64 with corretto 11 and an application cds archive. production application archives, x86-64 and kubernetes remain untested.
