package main

import "time"

const (
	// SecondInstanceWait is the bounded wait window when a second launch hits
	// the single-instance mutex before the first instance has created its tray
	// window or written launcher-runtime.json.
	SecondInstanceWait = 2 * time.Second
	SecondInstancePoll = 100 * time.Millisecond
)

type SecondInstanceOutcome int

const (
	OutcomeOpenedExisting SecondInstanceOutcome = iota
	OutcomeSignaledTray
	OutcomeUnresponsive
)

type ActivateDecision int

const (
	ActivateIgnore ActivateDecision = iota
	ActivateOpenBrowser
	ActivateWaitAndOpen
	ActivateRestartAndOpen
)

// DecideTrayActivate determines what the primary tray host should do when a
// second launch asks it to activate (or when the user clicks "Open").
func DecideTrayActivate(running, starting, busy, shutting bool) ActivateDecision {
	if shutting {
		return ActivateIgnore
	}
	if running {
		return ActivateOpenBrowser
	}
	if starting || busy {
		return ActivateWaitAndOpen
	}
	return ActivateRestartAndOpen
}

// HandleSecondInstance coordinates a second PktPathStudio.exe launch when the
// single-instance mutex already exists:
//  1. If the existing backend is already healthy, open it right away.
//  2. Otherwise, locate the primary tray window and ask it to activate/restart
//     the backend and open the browser (no 8-second silent stall).
//  3. Only if neither a healthy backend nor a tray window appears within the
//     bounded wait window, report OutcomeUnresponsive so the caller can show a
//     clear message instead of exiting silently.
func HandleSecondInstance(
	probe func() (string, bool),
	findWindow func() uintptr,
	postActivate func(hwnd uintptr, noOpen bool) bool,
	openURL func(url string),
	noOpen bool,
	waitFor time.Duration,
	poll time.Duration,
) SecondInstanceOutcome {
	if poll <= 0 {
		poll = SecondInstancePoll
	}
	if url, ok := probe(); ok {
		if !noOpen && url != "" && openURL != nil {
			openURL(url)
		}
		return OutcomeOpenedExisting
	}
	deadline := time.Now().Add(waitFor)
	for {
		if hwnd := findWindow(); hwnd != 0 {
			if postActivate(hwnd, noOpen) {
				return OutcomeSignaledTray
			}
		}
		if url, ok := probe(); ok {
			if !noOpen && url != "" && openURL != nil {
				openURL(url)
			}
			return OutcomeOpenedExisting
		}
		if !time.Now().Before(deadline) {
			return OutcomeUnresponsive
		}
		time.Sleep(poll)
	}
}
