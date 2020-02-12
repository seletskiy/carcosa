package carcosa

import (
	"github.com/seletskiy/carcosa/pkg/carcosa/auth"
)

type SyncStatsSide struct {
	Add int `json:"add"`
	Del int `json:"del"`
}

type SyncStats struct {
	Ours SyncStatsSide `json:"ours"`
	Thys SyncStatsSide `json:"thys"`
}

// Sync performs local <-> remote sync according to the following algorithm.
//
// Carcosa leverages single-character suffix which is appended to ref name to
// distinguish between remote only, locally added refs and locally deleted
// refs:
//
// * refs/tokens/<encrypted-token-name-in-hex>[<suffix>],
//   where *optional* <suffix> is one of:
//   * '=': token from remote, exists only during sync,
//   * '+': locally added token, not yet pushed,
//   * '-': locally added token, not yet pushed.
//
//  * for locally added tokens there will be *two* refs
//    * one with '+' suffix
//    * and one without, meaning that ref was added but not yet pushed.
//
//  * for locally deleted tokens there will be *one* ref:
//    * one with '-' suffix, meaning that corresponding ref without '-' suffix
//      was deleted.
//
// Sync algorithm:
//
// 1) (pull)
//    $ git pull refs/tokens/*:refs/tokens/*=
//    * all remote refs will be pulled to local refs ending with '=' suffix
//
// 2) (sort)
//    Go over refs/tokens/* list and sort refs to 4 buckets:
//    * 'thys' (remote refs): if ref ends with '=',
//    * 'adds' (locally added refs): if ref ends with '+',
//    * 'dels' (locally deleted refs): if ref ends with '-',
//    * 'ours' (previously pulled refs): otherwise.
//
// 3) (mark for remote add)
//    Go over 'adds' bucket and add ref with same token name, but with '=' suffix.
//    Add ref to remote refs bucket 'thys'.
//
// 4) (mark for remote delete)
//    Go over 'dels' bucket and if same token exists in remote refs bucket 'thys',
//    then delete ref with same token name, but with '=' suffix.
//    Remove ref from remote refs bucket 'thys'.
//
// 5) (push-prune remote), if 'push' argument is true
//    $ git push refs/tokens/*=:refs/tokens/* --prune
//    * this will overwrite remote refs with those which only present locally.
//
// 6) (cleanup)
//    Remove refs with '+' and '-' suffixes locally.
//
// 7) (prune local)
//    Go over local refs bucket 'ours' and remove all that have no
//    corresponding ref with '=' suffix (e.g ref is not 'thys' bucket).
//    * this will delete all local refs which were deleted from another location.
//
// 8) (add remote-only refs to local)
//    Go over remote refs bucket 'thys' and add ref locally if it's not
//    present.
//    * this will add all remote refs which were added from another location.

func (repo *repo) Sync(
	remote string,
	ns string,
	auth auth.Auth,
	push bool,
) (*SyncStats, error) {
	log.Infof("{sync} with: %s", remote)

	err := repo.lock()
	if err != nil {
		return nil, err
	}

	defer func() {
		err := repo.unlock()
		if err != nil {
			log.Error(err)
		}
	}()

	err = repo.pull(remote, refspec(ns), auth)
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
