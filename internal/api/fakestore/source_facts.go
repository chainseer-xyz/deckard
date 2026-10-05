package fakestore

import (
	"reflect"
	"slices"

	"github.com/chainseer-xyz/deckard/internal/model"
)

func assetHasSource(a model.Asset, source string) bool {
	return a.Source == source || slices.Contains(a.Reporters, source)
}

// cloneAsset keeps callers from changing the stored asset through JSON maps
// or slices. The canonical facts and each reporter's facts are independent.
func cloneAsset(a model.Asset) model.Asset {
	a.Attrs = cloneAttrs(a.Attrs)
	a.Reporters = slices.Clone(a.Reporters)
	if a.SourceFacts != nil {
		facts := make(map[string]model.SourceFact, len(a.SourceFacts))
		for source, fact := range a.SourceFacts {
			fact.Attrs = cloneAttrs(fact.Attrs)
			facts[source] = fact
		}
		a.SourceFacts = facts
	}
	if a.RemovedAt != nil {
		removed := *a.RemovedAt
		a.RemovedAt = &removed
	}
	return a
}

func cloneAttrs(attrs map[string]any) map[string]any {
	if attrs == nil {
		return nil
	}
	out := make(map[string]any, len(attrs))
	for key, value := range attrs {
		out[key] = cloneAttr(value)
	}
	return out
}

func cloneAttr(value any) any {
	if value == nil {
		return nil
	}
	return cloneAttrValue(reflect.ValueOf(value)).Interface()
}

// JSON fixtures may use typed maps/slices as well as decoded map[string]any
// and []any. Keep their types while recursively isolating every container.
func cloneAttrValue(value reflect.Value) reflect.Value {
	switch value.Kind() {
	case reflect.Interface:
		if !value.IsNil() {
			out := reflect.New(value.Type()).Elem()
			out.Set(cloneAttrValue(value.Elem()))
			return out
		}
	case reflect.Map:
		if !value.IsNil() {
			out := reflect.MakeMapWithSize(value.Type(), value.Len())
			items := value.MapRange()
			for items.Next() {
				out.SetMapIndex(items.Key(), cloneAttrValue(items.Value()))
			}
			return out
		}
	case reflect.Slice:
		if !value.IsNil() {
			out := reflect.MakeSlice(value.Type(), value.Len(), value.Len())
			for i := range value.Len() {
				out.Index(i).Set(cloneAttrValue(value.Index(i)))
			}
			return out
		}
	case reflect.Array:
		out := reflect.New(value.Type()).Elem()
		for i := range value.Len() {
			out.Index(i).Set(cloneAttrValue(value.Index(i)))
		}
		return out
	}
	return value
}
