#include <system.h>
#include <muscan/scanner.hh>
#include <Muhelp/Muconf.hh>
#include <NewNet/nnlog.h>

#include <iostream>
#include <cstdlib>
#include <algorithm>
#include <vector>
#include <unistd.h>

using std::string;
using std::map;
using std::cout;
using std::endl;
using std::cerr;
using std::vector;

class FAMHandler
{
public:
    FAMHandler(const string& config_file, bool doBuddy, bool doReload);
    ~FAMHandler();

    int load();
    int run();
    void save();

    void remove(void*);
    void add(void*);

private:
    string shares, state;
    DirScanner *root;
    time_t save_at;
    bool m_doReload;
};

FAMHandler::FAMHandler(const string& config_file, bool doBuddy, bool doReload)
    : save_at(0), root(0)
{
    if (Scanner_Verbosity >= 2){
        NNLOG.logEvent.connect(new NewNet::ConsoleOutput);
        NNLOG.enable("ALL");
    }

    m_doReload = doReload;

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

FAMHandler::~FAMHandler()
{
    if(root)
        delete root;
}

int FAMHandler::load()
{
    if(root)
        delete root;

    root = new DirScanner();
    root->load(state);
    root->scan();

    return 0;
}

void FAMHandler::save()
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

int FAMHandler::run()
{
    // Simple polling loop: scan and detect changes periodically.
    while(1)
    {
        root->real_scan();
        // Always save after a scan cycle (simple behavior for macOS polling fallback)
        save();
        sleep(5);
    }
    return 0;
}

void FAMHandler::add(void*) {}
void FAMHandler::remove(void*) {}

int main(int argc, char **argv)
{
#ifdef RELAYED_LIBFAM
    extern int libfam_is_present;
    if(! libfam_is_present)
    {
        cerr << "libfam not found, aborting" << endl;
        return -1;
    }
#endif
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

    FAMHandler fh(config_file, doBuddy, doReload);
    if(fh.load())
        return -1;
    fh.run();

    return 0;
}
