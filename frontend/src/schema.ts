import featureNames from "../../data/model_feature_names.json";

export const FEATURE_NAMES: readonly string[] = Object.freeze(featureNames);
export const EXPECTED_FEATURE_COUNT = 48;

export function matchesReleaseSchema(names: unknown): names is string[] {
  return Array.isArray(names)
    && names.length === EXPECTED_FEATURE_COUNT
    && names.every((name, index) => name === FEATURE_NAMES[index]);
}
