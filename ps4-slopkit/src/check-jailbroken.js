export function checkJailbroken({ sc, sys, mark = () => { }, state = () => { } }) {
    const pid = sc(sys.getpid).i32;
    const uid = sc(sys.getuid).i32;
    const euid = sc(sys.geteuid).i32;
    const setuidProbe = sc(sys.setuid, 0).i32;

    mark("PID", String(pid));
    mark("UID", "uid=" + uid + " euid=" + euid
        + " setuid(0)=" + setuidProbe);

    const alreadyJailbroken = uid === 0 || euid === 0 || setuidProbe === 0;
    if (alreadyJailbroken) {
        mark("ALREADY-JAILBROKEN", "setuid(0) succeeded; exploit stopped");
        state("Already jailbroken", "error");
    }

    return { pid, uid, euid, setuidProbe, alreadyJailbroken };
}
