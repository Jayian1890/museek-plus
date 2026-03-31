#pragma once

namespace Museek { class Museekd; }

// Start an embedded museekd instance and run its reactor on a background thread.
// Best-effort: failures are silently ignored so GUI can still operate in remote-mode.
void start_embedded_museekd();

// Stop the embedded museekd instance (if any) and join its reactor thread.
void stop_embedded_museekd();

// Return pointer to the embedded museekd instance or nullptr if none.
Museek::Museekd * get_embedded_museekd();
