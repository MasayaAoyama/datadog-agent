// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2023-present Datadog, Inc.
//go:build windows
// +build windows

package eventlog

import (
	"fmt"
	"sync"

	// "github.com/DataDog/datadog-agent/comp/core/log"
	pkglog "github.com/DataDog/datadog-agent/pkg/util/log"
	"golang.org/x/sys/windows"
)

const (
	// Timeout on pull event handle in milliseconds
	// Controls how often the poll goroutine will check for Stop()
	GET_EVENT_LOOP_WAIT_MS = 50

	// How many events to fetch per EvtNext call
	EVENT_BATCH_COUNT = 64

	// Break EvtNext loop and return to mainLoop after this many events
	MAX_EVENT_LOOP_COUNT = 1000
)

type QuerySubscription struct {
	// User gets EventRecords from this channel
	EventRecords chan *EventRecord

	// datadog components
	//log log.Component

	// Windows API
	subscriptionHandle EventResultSetHandle
	waitEventHandle WaitEventHandle

	// Query loop management
	started bool
	queryLoopWaiter sync.WaitGroup
	stopQueryLoop chan bool
}

type EventRecord struct {
	EventRecordHandle EventRecordHandle
}

func newSubscriptionWaitEvent() (WaitEventHandle, error) {
	// https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-createeventa
	// Manual reset, initally set
	hEvent, err := windows.CreateEvent(nil, 1, 1, nil)
	return WaitEventHandle(hEvent), err
}

//func NewQuerySubscription(log log.Component) *QuerySubscription {
func NewQuerySubscription() *QuerySubscription {
	var q QuerySubscription
	q.subscriptionHandle = EventResultSetHandle(0)
	q.waitEventHandle = WaitEventHandle(0)
	// q.log = log

	return &q
}

func (q *QuerySubscription) Start(ChannelPath, Query string) (error) {

	if q.started {
		return fmt.Errorf("Query subscription is already started")
	}

	// create event
	hWait, err := newSubscriptionWaitEvent()
	if err != nil {
		return err
	}

	// create subscription
	hSub, err := EvtSubscribe(
		hWait,
		ChannelPath,
		Query,
		EvtSubscribeToFutureEvents)
	if err != nil {
		safeCloseNullHandle(windows.Handle(hWait))
		return err
	}

	q.stopQueryLoop = make(chan bool)
	q.EventRecords = make(chan *EventRecord)
	q.waitEventHandle = hWait
	q.subscriptionHandle = hSub

	// start goroutine to query events for channel
	q.queryLoopWaiter.Add(1)
	go q.queryLoop()
	q.started = true

	return nil
}

func (q *QuerySubscription) queryLoop() {
	defer q.queryLoopWaiter.Done()

	queryLoop:
		for {
			select {
			case <- q.stopQueryLoop:
				break queryLoop
			default:
				if q.eventsAvailable() {
					_ = q.collectEvents()
				}
			}
		}
}

func (q *QuerySubscription) eventsAvailable() bool {
	// Windows sets waitEventHandle when event records are available
	dwWait, err := windows.WaitForSingleObject(windows.Handle(q.waitEventHandle), GET_EVENT_LOOP_WAIT_MS)
	if err != nil {
		// WAIT_FAILED
		pkglog.Errorf("WaitForSingleObject failed: %d %#x", err)
		// TODO: Should we Stop() ?
		return false
	}

	if dwWait == windows.WAIT_OBJECT_0 {
		// Event is set, events records are ready
		return true
	} else if dwWait == uint32(windows.WAIT_TIMEOUT) {
		// timeout
	} else {
		// some other error occurred
		gle := windows.GetLastError()
		pkglog.Errorf("WaitForSingleObject unknown error: wait(%d,%#x) gle(%d,%#x)",
			dwWait,
			dwWait,
			gle,
			gle)
		// TODO: Should we Stop() ?
	}

	return false
}

func (q *QuerySubscription) collectEvents() error {

	eventCount := 0
	for {
		// TODO: should we use infinite or a small value?
		//       it shouldn't block or timeout because we had out event set?
		eventRecordHandles, err := EvtNext(q.subscriptionHandle, EVENT_BATCH_COUNT, windows.INFINITE)
		if err == nil {
			// got events, process them and send them to the channel
			eventRecords := q.parseEventRecordHandles(eventRecordHandles)
			q.sendEventsToChannel(eventRecords)
			eventCount += len(eventRecordHandles)
		} else if err == windows.ERROR_TIMEOUT {
			// no more events
			// TODO: Should we reset the handle? MS example says no
			break
		} else if err == windows.ERROR_NO_MORE_ITEMS {
			// no more events
			// reset wait event handle
			windows.ResetEvent(windows.Handle(q.waitEventHandle))
			break
		} else {
			pkglog.Errorf("EvtNext failed: %d %#x", err, err)
		}

		// Check max so we can return and check for Stop()
		if eventCount >= MAX_EVENT_LOOP_COUNT {
			break
		}
	}

	return nil
}

func (q *QuerySubscription) parseEventRecordHandles(eventRecordHandles []EventRecordHandle) []*EventRecord {
	var err error

	eventRecords := make([]*EventRecord, len(eventRecordHandles))

	for i, eventRecordHandle := range eventRecordHandles {
		pkglog.Errorf("%d %v", i, eventRecordHandle)
		pkglog.Flush()
		eventRecords[i], err = q.parseEventRecordHandle(eventRecordHandle)
		if err != nil {
			pkglog.Errorf("Failed to process event (%#x): %v", eventRecordHandle, err)
		}
	}

	return eventRecords
}

func (q *QuerySubscription) parseEventRecordHandle(eventRecordHandle EventRecordHandle) (*EventRecord, error) {
	var e EventRecord
	e.EventRecordHandle = eventRecordHandle
	// TODO: Render?
	return &e, nil
}

func (q *QuerySubscription) sendEventsToChannel(eventRecords []*EventRecord) error {
	for _, eventRecord := range eventRecords {
		q.EventRecords <- eventRecord
	}
	return nil
}

func (q *QuerySubscription) Stop() {
	// Wait for queryLoop to stop
	q.stopQueryLoop <- true
	q.queryLoopWaiter.Wait()

	// Sender loop is stopped, close the channel now
	close(q.EventRecords)

	// Cleanup Windows API
	EvtCloseResultSet(q.subscriptionHandle)
	safeCloseNullHandle(windows.Handle(q.waitEventHandle))

	q.started = false
}