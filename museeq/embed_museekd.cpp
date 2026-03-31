#include "embed_museekd.h"
#include <museekd/museekd.h>
#include <museekd/configmanager.h>
#include <NewNet/nnreactor.h>
#include <thread>
#include <cstdlib>
#include <memory>
#include <atomic>
#include <QCoreApplication>
#include <QObject>
#include <QDebug>

static std::unique_ptr<Museek::Museekd> g_embeddedDaemon;
static std::unique_ptr<std::thread> g_reactorThread;
static std::atomic<bool> g_embeddedRunning(false);

void stop_embedded_museekd()
{
    if(!g_embeddedRunning.load()) return;

    if(g_embeddedDaemon && g_embeddedDaemon->reactor()) {
        try {
            g_embeddedDaemon->reactor()->stop();
        } catch(...) {}
    }

    if(g_reactorThread && g_reactorThread->joinable()) {
        try { g_reactorThread->join(); } catch(...) {}
    }

    g_reactorThread.reset();
    g_embeddedDaemon.reset();
    g_embeddedRunning.store(false);
}

void start_embedded_museekd()
{
    try {
        if(g_embeddedRunning.load()) return;

        g_embeddedDaemon.reset(new Museek::Museekd(nullptr));
        qDebug() << "embed_museekd: constructed Museekd at" << (void*)g_embeddedDaemon.get();
        const char *home = std::getenv("HOME");
        if (home) {
            std::string cfg = std::string(home) + std::string("/.museekd/config.xml");
            qDebug() << "embed_museekd: loading config from" << cfg.c_str();
            g_embeddedDaemon->config()->load(cfg);
        }
        g_embeddedDaemon->LoadShares();
        g_embeddedDaemon->LoadDownloads();
        qDebug() << "embed_museekd: loaded shares and downloads";

        // Start reactor on a managed thread so we can stop/join it cleanly
        g_reactorThread.reset(new std::thread([](){
            if (g_embeddedDaemon && g_embeddedDaemon->reactor()) {
                qDebug() << "embed_museekd: reactor thread starting";
                g_embeddedRunning.store(true);
                g_embeddedDaemon->reactor()->run();
                qDebug() << "embed_museekd: reactor thread exited";
            }
        }));

        // If a QCoreApplication exists, hook into aboutToQuit to stop the reactor
        if(QCoreApplication::instance()) {
            QObject::connect(QCoreApplication::instance(), &QCoreApplication::aboutToQuit, [](){
                stop_embedded_museekd();
            });
        }
    } catch(...) {
        // ignore failures, GUI can still operate in remote mode
        stop_embedded_museekd();
    }
}

Museek::Museekd * get_embedded_museekd()
{
    return g_embeddedDaemon.get();
}
