#include <system.h>
#include <muscan/scanner.hh>
#include <Muhelp/Muconf.hh>
#include <NewNet/nnlog.h>

#include <iostream>
#include <cstdlib>
#include <algorithm>
#include <vector>
#include <unistd.h>
#include <fcntl.h>
#include <sys/event.h>
#include <sys/time.h>
#include <dirent.h>

using std::string;
using std::map;
using std::cout;
using std::endl;
using std::cerr;
using std::vector;

class KQHandler
{
public:
    KQHandler(const string& config_file, bool doBuddy, bool doReload);
    ~KQHandler();

    int load();
    int run();
    void save();

private:
    string shares, state;
    DirScanner *root;
    bool m_doReload;

    int kq;
    vector<int> fds;

    void register_all_dirs(DirEntry *entry);
    void register_dir(const string &path);
    void close_all();
};

KQHandler::KQHandler(const string& config_file, bool doBuddy, bool doReload)
    : root(0), m_doReload(doReload), kq(-1)
{
    if (Scanner_Verbosity >= 2){
        NNLOG.logEvent.connect(new NewNet::ConsoleOutput);
        NNLOG.enable("ALL");
    }

    Muconf config(config_file);
    if(! config.hasDomain("shares") || ! config["shares"].hasKey("database")) {
        cerr << "config file '" << config_file << "' incomplete or corrupt shares" << endl;
        exit(-1);
    }
    if(! config.hasDomain("buddy.shares") || ! config["buddy.shares"].hasKey("database")) {
        cerr << "config file '" << config_file << "' incomplete or corrupt buddy shares" << endl;
        exit(-1);
    }

    if (doBuddy)
    {
        string tmp = config["buddy.shares"]["database"];
        shares = tmp;
        state = shares + ".state";
    }
    else {
        string tmp = config["shares"]["database"];
        shares = tmp;
        state = shares + ".state";
    }
}

KQHandler::~KQHandler()
{
    close_all();
    if(root)
        delete root;
}

int KQHandler::load()
{
    if(root)
        delete root;

    root = new DirScanner();
    root->load(state);
    root->scan();

    // create kqueue
    kq = kqueue();
    if(kq == -1) {
        perror("kqueue");
        return -1;
    }

    // register all directories
    register_all_dirs(root);

    return 0;
}

void KQHandler::register_all_dirs(DirEntry *entry)
{
    // register the directory itself
    if(!entry->path.empty())
        register_dir(entry->path);

    for(auto &p : entry->folders) {
        register_all_dirs(p.second);
    }
}

void KQHandler::register_dir(const string &path)
{
#ifndef O_EVTONLY
#define O_EVTONLY O_RDONLY
#endif
    int fd = open(path.c_str(), O_EVTONLY);
    if(fd == -1)
    {
        // ignore
        return;
    }

    struct kevent kev;
    EV_SET(&kev, fd, EVFILT_VNODE, EV_ADD | EV_ENABLE | EV_CLEAR,
           NOTE_WRITE | NOTE_EXTEND | NOTE_ATTRIB | NOTE_DELETE | NOTE_RENAME,
           0, (void*)path.c_str());
    if(kevent(kq, &kev, 1, NULL, 0, NULL) == -1)
    {
        close(fd);
        return;
    }
    fds.push_back(fd);
}

void KQHandler::close_all()
{
    for(int fd : fds)
        close(fd);
    fds.clear();
    if(kq != -1)
        close(kq);
    kq = -1;
}

void KQHandler::save()
{
    root->save(state);

    DirEntry folded;

    root->fold(&folded);
    folded.save(shares);
#ifndef WIN32
    if (m_doReload)
        system("killall -HUP museekd");
#endif // WIN32
}

int KQHandler::run()
{
    const int MAX_EVENTS = 16;
    struct kevent events[MAX_EVENTS];

    while(1)
    {
        int nev = kevent(kq, NULL, 0, events, MAX_EVENTS, NULL);
        if(nev == -1)
        {
            perror("kevent");
            return -1;
        }

        bool changed = false;
        for(int i = 0; i < nev; ++i)
        {
            // We received a notification for a watched directory. Trigger a scan.
            changed = true;
        }

        if(changed)
        {
            // Refresh tree and save
            root->real_scan();
            save();

            // Re-register directories in case new folders appeared
            close_all();
            kq = kqueue();
            if(kq == -1) return -1;
            register_all_dirs(root);
        }
    }

    return 0;
}

int main(int argc, char **argv)
{
    string config_file = string(getenv("HOME")) + "/.museekd/config.xml";
    bool doBuddy = false;
    bool doReload = true;
    for(int i = 1; i < argc; i++) {
        string arg = argv[i];
        if(arg == "-c" || arg == "--config") {
            ++i;
            config_file = string(argv[i]);
        }
        else if(arg == "-b" || arg == "--buddy") {
            ++i;
            doBuddy = true;
        }
        else if(arg == "-h" || arg == "--help") {
            ++i;
            cerr << "muscand [-c --config PATH] [-b --buddy] [-h --help] [-v --verbose] [--no-reload]" << endl;
            cerr << "Version 0.2.0" << endl;
            exit(-1);
        }
        else if(arg == "-v" || arg == "--verbose") {
            Scanner_Verbosity += 1;
        }
        else if(arg == "--no-reload") {
            doReload = false;
        }
    }

    KQHandler fh(config_file, doBuddy, doReload);
    if(fh.load())
        return -1;
    fh.run();

    return 0;
}
