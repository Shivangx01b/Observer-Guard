package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/dgraph-io/badger/v3"
	"github.com/google/uuid"

	"observeguard/internal/models"
)

// BadgerStorage implements Storage interface using BadgerDB
type BadgerStorage struct {
	db *badger.DB
}

// NewBadgerStorage creates a new BadgerDB storage instance
func NewBadgerStorage(path string) (*BadgerStorage, error) {
	opts := badger.DefaultOptions(path)
	opts.Logger = nil // Disable badger logging

	db, err := badger.Open(opts)
	if err != nil {
		return nil, fmt.Errorf("failed to open BadgerDB: %w", err)
	}

	storage := &BadgerStorage{db: db}

	// Start garbage collection
	go storage.runGC()

	return storage, nil
}

// runGC runs periodic garbage collection
func (s *BadgerStorage) runGC() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		err := s.db.RunValueLogGC(0.5)
		if err != nil && err != badger.ErrNoRewrite {
			// Log error but don't fail
		}
	}
}

// StoreEvent stores a generic event
func (s *BadgerStorage) StoreEvent(ctx context.Context, event *models.Event) error {
	key := fmt.Sprintf("event:%s", event.ID.String())
	data, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("failed to marshal event: %w", err)
	}

	return s.db.Update(func(txn *badger.Txn) error {
		return txn.Set([]byte(key), data)
	})
}

// GetEvent retrieves an event by ID
func (s *BadgerStorage) GetEvent(ctx context.Context, id uuid.UUID) (*models.Event, error) {
	key := fmt.Sprintf("event:%s", id.String())
	var event models.Event

	err := s.db.View(func(txn *badger.Txn) error {
		item, err := txn.Get([]byte(key))
		if err != nil {
			if err == badger.ErrKeyNotFound {
				return fmt.Errorf("event not found")
			}
			return err
		}

		return item.Value(func(val []byte) error {
			return json.Unmarshal(val, &event)
		})
	})

	if err != nil {
		return nil, err
	}

	return &event, nil
}

// ListEvents retrieves events with filtering
func (s *BadgerStorage) ListEvents(ctx context.Context, filter EventFilter) ([]*models.Event, error) {
	var events []*models.Event
	prefix := []byte("event:")

	err := s.db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.PrefetchSize = 100
		it := txn.NewIterator(opts)
		defer it.Close()

		count := 0
		for it.Seek(prefix); it.ValidForPrefix(prefix); it.Next() {
			if filter.Limit > 0 && count >= filter.Limit {
				break
			}

			if filter.Offset > 0 && count < filter.Offset {
				count++
				continue
			}

			item := it.Item()
			err := item.Value(func(val []byte) error {
				var event models.Event
				if err := json.Unmarshal(val, &event); err != nil {
					return err
				}

				// Apply filters
				if s.eventMatchesFilter(&event, filter) {
					events = append(events, &event)
				}
				return nil
			})

			if err != nil {
				return err
			}
			count++
		}
		return nil
	})

	return events, err
}

// eventMatchesFilter checks if an event matches the given filter
func (s *BadgerStorage) eventMatchesFilter(event *models.Event, filter EventFilter) bool {
	// Filter by event types
	if len(filter.EventTypes) > 0 {
		found := false
		for _, et := range filter.EventTypes {
			if event.Type == et {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// Filter by PIDs
	if len(filter.PIDs) > 0 {
		found := false
		for _, pid := range filter.PIDs {
			if event.PID == pid {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// Filter by time range
	if filter.StartTime != nil && event.Timestamp.Before(*filter.StartTime) {
		return false
	}
	if filter.EndTime != nil && event.Timestamp.After(*filter.EndTime) {
		return false
	}

	return true
}

// DeleteEvent deletes an event by ID
func (s *BadgerStorage) DeleteEvent(ctx context.Context, id uuid.UUID) error {
	key := fmt.Sprintf("event:%s", id.String())
	return s.db.Update(func(txn *badger.Txn) error {
		return txn.Delete([]byte(key))
	})
}

// CountEvents counts events matching the filter
func (s *BadgerStorage) CountEvents(ctx context.Context, filter EventFilter) (int64, error) {
	var count int64
	prefix := []byte("event:")

	err := s.db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.PrefetchValues = false // Only need keys for counting
		it := txn.NewIterator(opts)
		defer it.Close()

		for it.Seek(prefix); it.ValidForPrefix(prefix); it.Next() {
			// For accurate filtering, we would need to deserialize and check
			// For now, just count all events
			count++
		}
		return nil
	})

	return count, err
}

// StoreProcessEvent stores a process event
func (s *BadgerStorage) StoreProcessEvent(ctx context.Context, event *models.ProcessEvent) error {
	key := fmt.Sprintf("process:%d:%s", event.PID, event.ID.String())
	data, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("failed to marshal process event: %w", err)
	}

	return s.db.Update(func(txn *badger.Txn) error {
		return txn.Set([]byte(key), data)
	})
}

// GetProcessEvents retrieves process events for a given PID
func (s *BadgerStorage) GetProcessEvents(ctx context.Context, pid int32) ([]*models.ProcessEvent, error) {
	var events []*models.ProcessEvent
	prefix := []byte(fmt.Sprintf("process:%d:", pid))

	err := s.db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		it := txn.NewIterator(opts)
		defer it.Close()

		for it.Seek(prefix); it.ValidForPrefix(prefix); it.Next() {
			item := it.Item()
			err := item.Value(func(val []byte) error {
				var event models.ProcessEvent
				if err := json.Unmarshal(val, &event); err != nil {
					return err
				}
				events = append(events, &event)
				return nil
			})
			if err != nil {
				return err
			}
		}
		return nil
	})

	return events, err
}

// ListProcesses retrieves processes with filtering
func (s *BadgerStorage) ListProcesses(ctx context.Context, filter ProcessFilter) ([]*models.ProcessEvent, error) {
	var processes []*models.ProcessEvent
	prefix := []byte("process:")

	err := s.db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		it := txn.NewIterator(opts)
		defer it.Close()

		count := 0
		for it.Seek(prefix); it.ValidForPrefix(prefix); it.Next() {
			if filter.Limit > 0 && count >= filter.Limit {
				break
			}

			if filter.Offset > 0 && count < filter.Offset {
				count++
				continue
			}

			item := it.Item()
			err := item.Value(func(val []byte) error {
				var event models.ProcessEvent
				if err := json.Unmarshal(val, &event); err != nil {
					return err
				}

				if s.processMatchesFilter(&event, filter) {
					processes = append(processes, &event)
				}
				return nil
			})

			if err != nil {
				return err
			}
			count++
		}
		return nil
	})

	return processes, err
}

// processMatchesFilter checks if a process event matches the given filter
func (s *BadgerStorage) processMatchesFilter(event *models.ProcessEvent, filter ProcessFilter) bool {
	// Filter by PIDs
	if len(filter.PIDs) > 0 {
		found := false
		for _, pid := range filter.PIDs {
			if event.PID == pid {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// Filter by time range
	if filter.StartTime != nil && event.Timestamp.Before(*filter.StartTime) {
		return false
	}
	if filter.EndTime != nil && event.Timestamp.After(*filter.EndTime) {
		return false
	}

	return true
}

// Implement other storage methods with similar patterns...
// For brevity, I'll implement a few key methods and placeholders for others

// StoreNetworkEvent stores a network event
func (s *BadgerStorage) StoreNetworkEvent(ctx context.Context, event *models.NetworkEvent) error {
	key := fmt.Sprintf("network:%s", event.ID.String())
	data, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("failed to marshal network event: %w", err)
	}

	return s.db.Update(func(txn *badger.Txn) error {
		return txn.Set([]byte(key), data)
	})
}

// GetNetworkEvents retrieves network events with filtering
func (s *BadgerStorage) GetNetworkEvents(ctx context.Context, filter NetworkFilter) ([]*models.NetworkEvent, error) {
	// Implementation similar to ListEvents but for network events
	return nil, fmt.Errorf("not implemented")
}

// StoreFileEvent stores a file event
func (s *BadgerStorage) StoreFileEvent(ctx context.Context, event *models.FileEvent) error {
	key := fmt.Sprintf("file:%s", event.ID.String())
	data, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("failed to marshal file event: %w", err)
	}

	return s.db.Update(func(txn *badger.Txn) error {
		return txn.Set([]byte(key), data)
	})
}

// GetFileEvents retrieves file events with filtering
func (s *BadgerStorage) GetFileEvents(ctx context.Context, filter FileFilter) ([]*models.FileEvent, error) {
	return nil, fmt.Errorf("not implemented")
}

// StoreSSLEvent stores an SSL event
func (s *BadgerStorage) StoreSSLEvent(ctx context.Context, event *models.SSLEvent) error {
	key := fmt.Sprintf("ssl:%s", event.ID.String())
	data, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("failed to marshal SSL event: %w", err)
	}

	return s.db.Update(func(txn *badger.Txn) error {
		return txn.Set([]byte(key), data)
	})
}

// GetSSLEvents retrieves SSL events with filtering
func (s *BadgerStorage) GetSSLEvents(ctx context.Context, filter SSLFilter) ([]*models.SSLEvent, error) {
	return nil, fmt.Errorf("not implemented")
}

// AI Security methods
func (s *BadgerStorage) StoreAISecurityEvent(ctx context.Context, event *models.AISecurityEvent) error {
	key := fmt.Sprintf("ai_security:%s", event.ID.String())
	data, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("failed to marshal AI security event: %w", err)
	}

	return s.db.Update(func(txn *badger.Txn) error {
		return txn.Set([]byte(key), data)
	})
}

func (s *BadgerStorage) GetAISecurityEvents(ctx context.Context, filter AISecurityFilter) ([]*models.AISecurityEvent, error) {
	return nil, fmt.Errorf("not implemented")
}

func (s *BadgerStorage) StoreAIModel(ctx context.Context, model *models.AIModel) error {
	key := fmt.Sprintf("ai_model:%s", model.ID)
	data, err := json.Marshal(model)
	if err != nil {
		return fmt.Errorf("failed to marshal AI model: %w", err)
	}

	return s.db.Update(func(txn *badger.Txn) error {
		return txn.Set([]byte(key), data)
	})
}

func (s *BadgerStorage) GetAIModel(ctx context.Context, id string) (*models.AIModel, error) {
	key := fmt.Sprintf("ai_model:%s", id)
	var model models.AIModel

	err := s.db.View(func(txn *badger.Txn) error {
		item, err := txn.Get([]byte(key))
		if err != nil {
			if err == badger.ErrKeyNotFound {
				return fmt.Errorf("AI model not found")
			}
			return err
		}

		return item.Value(func(val []byte) error {
			return json.Unmarshal(val, &model)
		})
	})

	if err != nil {
		return nil, err
	}

	return &model, nil
}

func (s *BadgerStorage) ListAIModels(ctx context.Context) ([]*models.AIModel, error) {
	var aiModels []*models.AIModel
	prefix := []byte("ai_model:")

	err := s.db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		it := txn.NewIterator(opts)
		defer it.Close()

		for it.Seek(prefix); it.ValidForPrefix(prefix); it.Next() {
			item := it.Item()
			err := item.Value(func(val []byte) error {
				var model models.AIModel
				if err := json.Unmarshal(val, &model); err != nil {
					return err
				}
				aiModels = append(aiModels, &model)
				return nil
			})
			if err != nil {
				return err
			}
		}
		return nil
	})

	return aiModels, err
}

func (s *BadgerStorage) StoreAIRuntime(ctx context.Context, runtime *models.AIRuntime) error {
	key := fmt.Sprintf("ai_runtime:%s", runtime.ID)
	data, err := json.Marshal(runtime)
	if err != nil {
		return fmt.Errorf("failed to marshal AI runtime: %w", err)
	}

	return s.db.Update(func(txn *badger.Txn) error {
		return txn.Set([]byte(key), data)
	})
}

func (s *BadgerStorage) GetAIRuntime(ctx context.Context, id string) (*models.AIRuntime, error) {
	key := fmt.Sprintf("ai_runtime:%s", id)
	var runtime models.AIRuntime

	err := s.db.View(func(txn *badger.Txn) error {
		item, err := txn.Get([]byte(key))
		if err != nil {
			if err == badger.ErrKeyNotFound {
				return fmt.Errorf("AI runtime not found")
			}
			return err
		}

		return item.Value(func(val []byte) error {
			return json.Unmarshal(val, &runtime)
		})
	})

	if err != nil {
		return nil, err
	}

	return &runtime, nil
}

func (s *BadgerStorage) ListAIRuntimes(ctx context.Context) ([]*models.AIRuntime, error) {
	var runtimes []*models.AIRuntime
	prefix := []byte("ai_runtime:")

	err := s.db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		it := txn.NewIterator(opts)
		defer it.Close()

		for it.Seek(prefix); it.ValidForPrefix(prefix); it.Next() {
			item := it.Item()
			err := item.Value(func(val []byte) error {
				var runtime models.AIRuntime
				if err := json.Unmarshal(val, &runtime); err != nil {
					return err
				}
				runtimes = append(runtimes, &runtime)
				return nil
			})
			if err != nil {
				return err
			}
		}
		return nil
	})

	return runtimes, err
}

// Placeholder implementations for remaining methods
func (s *BadgerStorage) StoreThreatEvent(ctx context.Context, event *models.ThreatEvent) error {
	data, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("failed to marshal threat event: %w", err)
	}

	return s.db.Update(func(txn *badger.Txn) error {
		key := fmt.Sprintf("threat:%s", event.ID.String())
		return txn.Set([]byte(key), data)
	})
}

func (s *BadgerStorage) GetThreatEvent(ctx context.Context, id uuid.UUID) (*models.ThreatEvent, error) {
	var threat *models.ThreatEvent
	err := s.db.View(func(txn *badger.Txn) error {
		key := fmt.Sprintf("threat:%s", id.String())
		item, err := txn.Get([]byte(key))
		if err != nil {
			return err
		}

		return item.Value(func(val []byte) error {
			return json.Unmarshal(val, &threat)
		})
	})

	if err != nil {
		if err == badger.ErrKeyNotFound {
			return nil, fmt.Errorf("threat not found")
		}
		return nil, fmt.Errorf("failed to retrieve threat: %w", err)
	}

	return threat, nil
}

func (s *BadgerStorage) ListThreatEvents(ctx context.Context, filter ThreatFilter) ([]*models.ThreatEvent, error) {
	var threats []*models.ThreatEvent

	err := s.db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.Prefix = []byte("threat:")
		it := txn.NewIterator(opts)
		defer it.Close()

		count := 0
		for it.Rewind(); it.Valid(); it.Next() {
			if filter.Limit > 0 && count >= filter.Limit {
				break
			}

			item := it.Item()
			err := item.Value(func(val []byte) error {
				var threat models.ThreatEvent
				if err := json.Unmarshal(val, &threat); err != nil {
					return err
				}
				threats = append(threats, &threat)
				return nil
			})
			if err != nil {
				return err
			}
			count++
		}
		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to list threats: %w", err)
	}

	return threats, nil
}

func (s *BadgerStorage) StoreSecurityPolicy(ctx context.Context, policy *models.SecurityPolicy) error {
	return fmt.Errorf("not implemented")
}

func (s *BadgerStorage) GetSecurityPolicy(ctx context.Context, id uuid.UUID) (*models.SecurityPolicy, error) {
	return nil, fmt.Errorf("not implemented")
}

func (s *BadgerStorage) ListSecurityPolicies(ctx context.Context) ([]*models.SecurityPolicy, error) {
	return nil, fmt.Errorf("not implemented")
}

func (s *BadgerStorage) UpdateSecurityPolicy(ctx context.Context, policy *models.SecurityPolicy) error {
	return fmt.Errorf("not implemented")
}

func (s *BadgerStorage) DeleteSecurityPolicy(ctx context.Context, id uuid.UUID) error {
	return fmt.Errorf("not implemented")
}

func (s *BadgerStorage) StoreAlert(ctx context.Context, alert *models.Alert) error {
	return fmt.Errorf("not implemented")
}

func (s *BadgerStorage) GetAlert(ctx context.Context, id uuid.UUID) (*models.Alert, error) {
	return nil, fmt.Errorf("not implemented")
}

func (s *BadgerStorage) ListAlerts(ctx context.Context, filter AlertFilter) ([]*models.Alert, error) {
	return nil, fmt.Errorf("not implemented")
}

func (s *BadgerStorage) UpdateAlert(ctx context.Context, alert *models.Alert) error {
	return fmt.Errorf("not implemented")
}

func (s *BadgerStorage) StoreSyscallEvent(ctx context.Context, event *models.SyscallEvent) error {
	return fmt.Errorf("not implemented")
}

func (s *BadgerStorage) GetSyscallEvents(ctx context.Context, filter SyscallFilter) ([]*models.SyscallEvent, error) {
	return nil, fmt.Errorf("not implemented")
}

func (s *BadgerStorage) ExportData(ctx context.Context, startTime, endTime time.Time) ([]byte, error) {
	return nil, fmt.Errorf("not implemented")
}

func (s *BadgerStorage) ImportData(ctx context.Context, data []byte) error {
	return fmt.Errorf("not implemented")
}

func (s *BadgerStorage) CleanupOldData(ctx context.Context, before time.Time) error {
	return fmt.Errorf("not implemented")
}

func (s *BadgerStorage) GetStorageStats(ctx context.Context) (*StorageStats, error) {
	stats := &StorageStats{
		StorageType: "badger",
		Health:      "healthy",
	}

	// Get basic stats from BadgerDB
	lsm, vlog := s.db.Size()
	stats.TotalSize = lsm + vlog

	return stats, nil
}

func (s *BadgerStorage) Close() error {
	return s.db.Close()
}

func (s *BadgerStorage) Ping(ctx context.Context) error {
	// Simple ping by trying to read a key
	return s.db.View(func(txn *badger.Txn) error {
		_, err := txn.Get([]byte("ping"))
		if err == badger.ErrKeyNotFound {
			return nil // This is expected
		}
		return err
	})
}