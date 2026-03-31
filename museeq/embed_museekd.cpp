#include "embed_museekd.h"
#include <museekd/museekd.h>
#include <museekd/configmanager.h>
#include <NewNet/nnreactor.h>
#include <thread>
#include <cstdlib>
#include <memory>

static std::unique_ptr<Museek::Museekd> g_embeddedDaemon;

void start_embedded_museekd()
{
    try {
        g_embeddedDaemon.reset(new Museek::Museekd(nullptr));
        const char *home = std::getenv("HOME");
        if (home) {
            std::string cfg = std::string(home) + std::string("/.museekd/config.xml");
            g_embeddedDaemon->config()->load(cfg);
        }
        g_embeddedDaemon->LoadShares();
        g_embeddedDaemon->LoadDownloads();
        std::thread([](){
            if (g_embeddedDaemon && g_embeddedDaemon->reactor())
                g_embeddedDaemon->reactor()->run();
        }).detach();
    } catch(...) {
        // ignore failures, GUI can still operate in remote mode
    }
}

Museek::Museekd * get_embedded_museekd()
{
    return g_embeddedDaemon.get();
}
