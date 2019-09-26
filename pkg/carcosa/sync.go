package carcosa

import (
	"github.com/seletskiy/carcosa/pkg/carcosa/auth"
)

type SyncStats struct {
	Ours, Thys struct {
		Add int
		Del int
	}
}

func (repo *repo) Sync(
	remote string,
	ns string,
	auth auth.Auth,
	push bool,
) (*SyncStats, error) {
	log.Infof("{sync} with: %s", remote)

	err := repo.pull(remote, refspec(ns), auth)
	if err != nil {
		return nil, err
	}

	refs, err := repo.list(ns)
	if err != nil {
		return nil, err
	}

	var (
		thys = map[string]ref{}
		ours = map[string]ref{}
		adds = map[string]ref{}
		dels = map[string]ref{}
	)

	for _, ref := range refs {
		switch {
		case ref.is(addition):
			adds[ref.token().name] = ref
		case ref.is(deletion):
			dels[ref.token().name] = ref
		case ref.is(external):
			thys[ref.token().name] = ref
		default:
			ours[ref.token().name] = ref
		}
	}

	var stats SyncStats

	for token, ref := range adds {
		thys[token] = ref.as(external)

		err = repo.update(thys[token])
		if err != nil {
			return nil, err
		}

		stats.Thys.Add++
	}

	if len(thys) != 0 {
		for token, _ := range dels {
			if ref, ok := thys[token]; ok {
				err := repo.delete(ref)
				if err != nil {
					return nil, err
				}

				delete(thys, token)

				stats.Thys.Del++
			}
		}

		if push {
			err = repo.push(remote, refspec(ns), auth)
			if err != nil {
				return nil, err
			}
		}
	}

	for _, ref := range dels {
		err := repo.delete(ref)
		if err != nil {
			return nil, err
		}
	}

	for _, ref := range adds {
		err := repo.delete(ref)
		if err != nil {
			return nil, err
		}
	}

	for token, ref := range ours {
		if _, ok := thys[token]; !ok {
			err := repo.delete(ref)
			if err != nil {
				return nil, err
			}

			stats.Ours.Del++
		}
	}

	for token, ref := range thys {
		if _, ok := ours[token]; !ok {
			err := repo.update(ref.token())
			if err != nil {
				return nil, err
			}

			stats.Ours.Add++
		}

		err = repo.delete(ref)
		if err != nil {
			return nil, err
		}
	}

	return &stats, nil
}
