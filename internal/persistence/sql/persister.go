package sql

import (
	"context"
	"embed"
	"fmt"
	"strconv"
	"time"

	"github.com/ory/x/popx"

	"github.com/cenkalti/backoff/v3"
	"github.com/ory/x/sqlcon"

	"github.com/ory/keto/internal/namespace"

	"github.com/gobuffalo/pop/v5"
	"github.com/ory/x/logrusx"
	"github.com/pkg/errors"

	"github.com/ory/keto/internal/persistence"
	"github.com/ory/keto/internal/x"
)

type (
	Persister struct {
		conn       *pop.Connection
		mb         *popx.MigrationBox
		namespaces namespace.Manager
		l          *logrusx.Logger
		dsn        string
	}
	internalPagination struct {
		Page, PerPage int
	}
	contextKeys string
)

const (
	transactionContextKey contextKeys = "ongoing transaction"
	defaultPageSize       int         = 100
)

var (
	//go:embed migrations/*.sql
	migrations embed.FS

	//go:embed namespace_migrations/*.sql
	namespaceMigrations embed.FS

	_ persistence.Persister = &Persister{}
)

func NewPersister(dsn string, l *logrusx.Logger, namespaces namespace.Manager) (*Persister, error) {
	pop.SetLogger(l.PopLogger)

	p := &Persister{
		namespaces: namespaces,
		l:          l,
		dsn:        dsn,
	}

	var err error
	p.conn, err = p.newConnection(nil)
	if err != nil {
		return nil, err
	}

	p.mb, err = popx.NewMigrationBox(migrations, popx.NewMigrator(p.conn, p.l, nil, 0))
	if err != nil {
		return nil, err
	}
	return p, nil
}

func (p *Persister) newConnection(options map[string]string) (c *pop.Connection, err error) {
	pool, idlePool, connMaxLifetime, cleanedDSN := sqlcon.ParseConnectionOptions(p.l, p.dsn)
	connDetails := &pop.ConnectionDetails{
		URL:             sqlcon.FinalizeDSN(p.l, cleanedDSN),
		IdlePool:        idlePool,
		ConnMaxLifetime: connMaxLifetime,
		Pool:            pool,
		Options:         options,
	}

	bc := backoff.NewExponentialBackOff()
	bc.MaxElapsedTime = time.Minute * 5
	bc.Reset()

	if err := backoff.Retry(func() (err error) {
		c, err = pop.NewConnection(connDetails)
		if err != nil {
			p.l.WithError(err).Warnf("Unable to connect to database, retrying.")
			return errors.WithStack(err)
		}

		if err := c.Open(); err != nil {
			p.l.WithError(err).Warnf("Unable to open the database connection, retrying.")
			return errors.WithStack(err)
		}

		if err := c.Store.(interface{ Ping() error }).Ping(); err != nil {
			return errors.WithStack(err)
		}

		return nil
	}, bc); err != nil {
		return nil, errors.WithStack(err)
	}

	return c, nil
}

func (p *Persister) MigrateUp(ctx context.Context) error {
	return errors.WithStack(p.mb.Up(ctx))
}

func (p *Persister) MigrateDown(ctx context.Context, steps int) error {
	return errors.WithStack(p.mb.Down(ctx, steps))
}

func (p *Persister) MigrationStatus(ctx context.Context) (popx.MigrationStatuses, error) {
	return p.mb.Status(ctx)
}

func (p *Persister) connection(ctx context.Context) *pop.Connection {
	tx := ctx.Value(transactionContextKey)
	if tx == nil {
		return p.conn.WithContext(ctx)
	}
	return tx.(*pop.Connection).WithContext(ctx)
}

func (p *Persister) transaction(ctx context.Context, f func(ctx context.Context, c *pop.Connection) error) error {
	tx := ctx.Value(transactionContextKey)
	if tx != nil {
		return f(ctx, tx.(*pop.Connection))
	}

	return p.conn.Transaction(func(tx *pop.Connection) error {
		return f(context.WithValue(ctx, transactionContextKey, tx), tx)
	})
}

func internalPaginationFromOptions(opts ...x.PaginationOptionSetter) (*internalPagination, error) {
	xp := x.GetPaginationOptions(opts...)
	ip := &internalPagination{
		PerPage: xp.Size,
	}
	if ip.PerPage == 0 {
		ip.PerPage = defaultPageSize
	}
	return ip, ip.parsePageToken(xp.Token)
}

func (p *internalPagination) parsePageToken(t string) error {
	if t == x.PageTokenEnd {
		p.PerPage = 0
		p.Page = 1
		return nil
	}

	if t == "" {
		p.Page = 1
		return nil
	}

	i, err := strconv.ParseUint(t, 10, 32)
	if err != nil {
		return errors.WithStack(persistence.ErrMalformedPageToken)
	}

	p.Page = int(i)
	return nil
}

func (p *internalPagination) encodeNextPageToken() string {
	return fmt.Sprintf("%d", p.Page+1)
}