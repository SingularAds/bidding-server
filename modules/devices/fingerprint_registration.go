package devices

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/go-redis/redis/v8"
	"golang.org/x/net/context"
)

type DeviceInfo struct {
	DeviceID    string    `json:"deviceId"`
	UserAgent   string    `json:"userAgent"`
	IPAddress   string    `json:"ipAddress"`
	Timestamp   time.Time `json:"timestamp"`
	Fingerprint string    `json:"fingerprint"`
}

type FingerprintRegistrationModule struct {
	redisClient *redis.Client
}

func NewFingerprintRegistrationModule(redisOptions *redis.Options) *FingerprintRegistrationModule {
	return &FingerprintRegistrationModule{
		redisClient: redis.NewClient(redisOptions),
	}
}

func (m *FingerprintRegistrationModule) GenerateFingerprint(deviceInfo *DeviceInfo) string {
	// Combine device characteristics to create a unique fingerprint
	fingerprintData := fmt.Sprintf("%s|%s|%d",
		deviceInfo.UserAgent,
		deviceInfo.IPAddress,
		time.Now().UnixNano(),
	)

	hash := sha256.Sum256([]byte(fingerprintData))
	return hex.EncodeToString(hash[:])
}

func (m *FingerprintRegistrationModule) RegisterDevice(ctx context.Context, deviceInfo *DeviceInfo) (string, error) {
	if deviceInfo.Fingerprint == "" {
		deviceInfo.Fingerprint = m.GenerateFingerprint(deviceInfo)
	}

	key := fmt.Sprintf("device:%s", deviceInfo.Fingerprint)

	err := m.redisClient.HMSet(ctx, key, map[string]interface{}{
		"deviceId":  deviceInfo.DeviceID,
		"userAgent": deviceInfo.UserAgent,
		"ipAddress": deviceInfo.IPAddress,
		"timestamp": deviceInfo.Timestamp.Unix(),
	}).Err()
	if err != nil {
		return "", fmt.Errorf("failed to register device: %v", err)
	}

	err = m.redisClient.Expire(ctx, key, 30*24*time.Hour).Err()
	if err != nil {
		return "", fmt.Errorf("failed to set device record expiration: %v", err)
	}

	return deviceInfo.Fingerprint, nil
}

func (m *FingerprintRegistrationModule) GetDeviceInfo(ctx context.Context, fingerprint string) (*DeviceInfo, error) {
	key := fmt.Sprintf("device:%s", fingerprint)

	result, err := m.redisClient.HGetAll(ctx, key).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve device info: %v", err)
	}

	if len(result) == 0 {
		return nil, fmt.Errorf("device not found")
	}

	timestamp, err := time.Unix(parseInt(result["timestamp"]), 0)
	if err != nil {
		return nil, fmt.Errorf("invalid timestamp: %v", err)
	}

	return &DeviceInfo{
		DeviceID:    result["deviceId"],
		UserAgent:   result["userAgent"],
		IPAddress:   result["ipAddress"],
		Timestamp:   timestamp,
		Fingerprint: fingerprint,
	}, nil
}

func (m *FingerprintRegistrationModule) Close() error {
	return m.redisClient.Close()
}

func parseInt(s string) int64 {
	val, _ := time.Parse(time.RFC3339, s)
	return val.Unix()
}
