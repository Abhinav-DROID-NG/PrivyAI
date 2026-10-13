package detector

import (
	"testing"
)

func TestDatabaseDetectorPasswordOnlyPositive(t *testing.T) {
	d := NewDatabaseDetector(DatabaseRedactPasswordOnly)

	tests := []struct {
		name             string
		input            string
		expectedPassword string
	}{
		{
			name:             "PostgreSQL postgres scheme",
			input:            "Connect to postgres://app_user:secret_postgres_pass@db.internal:5432/mydb now",
			expectedPassword: "secret_postgres_pass",
		},
		{
			name:             "PostgreSQL postgresql scheme",
			input:            "URI postgresql://admin:super_secret_pw@db.corp.net:5432/prod ready",
			expectedPassword: "super_secret_pw",
		},
		{
			name:             "MySQL scheme",
			input:            "DB: mysql://root:mysql_pass_123@127.0.0.1:3306/app_db config",
			expectedPassword: "mysql_pass_123",
		},
		{
			name:             "MongoDB standard scheme",
			input:            "Mongo: mongodb://dbuser:mongo_secret_pwd@cluster.local:27017/analytics",
			expectedPassword: "mongo_secret_pwd",
		},
		{
			name:             "MongoDB SRV scheme",
			input:            "Atlas mongodb+srv://clusteradmin:atlas_secret_pwd@cluster.mongodb.net/prod active",
			expectedPassword: "atlas_secret_pwd",
		},
		{
			name:             "Redis scheme",
			input:            "Cache redis://default:redis_pass_999@redis.host:6379/0 loaded",
			expectedPassword: "redis_pass_999",
		},
		{
			name:             "Redis SSL rediss scheme",
			input:            "Secure cache rediss://default:rediss_secret_token@cache.host:6380/1",
			expectedPassword: "rediss_secret_token",
		},
		{
			name:             "AMQP RabbitMQ scheme",
			input:            "Queue amqp://guest:rabbit_mq_secret@rabbitmq.internal:5672/vhost",
			expectedPassword: "rabbit_mq_secret",
		},
		{
			name:             "ADO Server Database Pwd form",
			input:            "Server=myServerAddress;Database=myDataBase;Uid=myUsername;Pwd=mySecretPassword;",
			expectedPassword: "mySecretPassword",
		},
		{
			name:             "ADO Data Source Password form",
			input:            "Data Source=192.168.1.100;Initial Catalog=sales;User ID=sa;Password=SqlAdminPass!;",
			expectedPassword: "SqlAdminPass!",
		},
		{
			name:             "ADO Reverse Password first form",
			input:            "Password=reverse_pass_123;Server=10.0.0.5;Database=users;",
			expectedPassword: "reverse_pass_123",
		},
		{
			name:             "JDBC URL with query password",
			input:            "Conn jdbc:postgresql://localhost:5432/mydb?user=postgres&password=jdbc_secret_pass ok",
			expectedPassword: "jdbc_secret_pass",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := d.Detect(tt.input)
			if len(findings) == 0 {
				t.Fatalf("expected finding for input %q, got none", tt.input)
			}
			f := findings[0]
			matched := tt.input[f.Start:f.End]
			if matched != tt.expectedPassword {
				t.Errorf("expected matched password %q, got %q", tt.expectedPassword, matched)
			}
			if f.Category != "database_credentials" {
				t.Errorf("expected category 'database_credentials', got %q", f.Category)
			}
			if f.Tier != TierT4Critical {
				t.Errorf("expected TierT4Critical, got %v", f.Tier)
			}
			if !f.Validated {
				t.Errorf("expected Validated=true")
			}
		})
	}
}

func TestDatabaseDetectorFullURLMode(t *testing.T) {
	d := NewDatabaseDetector(DatabaseRedactFullURL)

	input := "Connect to postgres://app_user:secret_postgres_pass@db.internal:5432/mydb immediately"
	expectedURL := "postgres://app_user:secret_postgres_pass@db.internal:5432/mydb"

	findings := d.Detect(input)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	f := findings[0]
	matched := input[f.Start:f.End]
	if matched != expectedURL {
		t.Errorf("expected full URL span %q, got %q", expectedURL, matched)
	}
	if f.Tier != TierT4Critical {
		t.Errorf("expected TierT4Critical, got %v", f.Tier)
	}
}

func TestDatabaseDetectorNegative(t *testing.T) {
	d := NewDatabaseDetector(DatabaseRedactPasswordOnly)

	negatives := []string{
		"Clean document with no database configuration",
		"postgres://localhost:5432/mydb without credentials",
		"postgresql://db.company.com/store without user or password",
		"mysql://127.0.0.1:3306/production without credentials",
		"mongodb://cluster.mongodb.net/test without credentials",
		"redis://redis-cluster.internal:6379 without credentials",
		"amqp://rabbitmq.internal:5672/vhost without credentials",
		"https://example.com/api/v1/users is a standard web link",
		"SELECT * FROM users WHERE status = 'active';",
		"Server=db.example.com;Database=mydb;Trusted_Connection=True; without password",
		"Placeholder [DATABASE_CREDENTIALS_REDACTED]",
	}

	for _, input := range negatives {
		t.Run(input, func(t *testing.T) {
			findings := d.Detect(input)
			if len(findings) > 0 {
				t.Fatalf("expected NO findings for negative input %q, got: %+v", input, findings)
			}
		})
	}
}

func TestDatabaseDetectorEdgeCases(t *testing.T) {
	d := NewDatabaseDetector(DatabaseRedactPasswordOnly)

	// Empty string
	if len(d.Detect("")) != 0 {
		t.Error("expected 0 findings for empty string")
	}

	// DB URL at start of string
	inputStart := "postgres://u:pass123@host:5432/db is active"
	findingsStart := d.Detect(inputStart)
	if len(findingsStart) != 1 {
		t.Fatalf("expected 1 finding at start, got: %+v", findingsStart)
	}
	if inputStart[findingsStart[0].Start:findingsStart[0].End] != "pass123" {
		t.Errorf("expected span pass123, got %q", inputStart[findingsStart[0].Start:findingsStart[0].End])
	}

	// DB URL at end of string
	inputEnd := "Config URI postgres://u:pass123@host:5432/db"
	findingsEnd := d.Detect(inputEnd)
	if len(findingsEnd) != 1 {
		t.Fatalf("expected 1 finding at end, got: %+v", findingsEnd)
	}
	if inputEnd[findingsEnd[0].Start:findingsEnd[0].End] != "pass123" {
		t.Errorf("expected span pass123, got %q", inputEnd[findingsEnd[0].Start:findingsEnd[0].End])
	}
}

func FuzzDatabaseDetector(f *testing.F) {
	f.Add("postgres://u:pass@host:5432/db")
	f.Add("Server=srv;Database=db;Pwd=secret;")
	f.Add("postgres://localhost:5432/mydb")
	f.Add("[DATABASE_CREDENTIALS_REDACTED]")
	f.Add("")

	d := NewDatabaseDetector(DatabaseRedactPasswordOnly)
	f.Fuzz(func(t *testing.T, text string) {
		findings := d.Detect(text)
		for _, f := range findings {
			if f.Start < 0 || f.Start >= f.End || f.End > len(text) {
				t.Fatalf("invalid span [%d, %d) for text length %d", f.Start, f.End, len(text))
			}
		}
	})
}
