#!/usr/bin/env python3
"""Offline schema conversion review. Never writes ROM trees or changes a device."""
import copy
import hashlib
import json
import math
from pathlib import Path
import xml.etree.ElementTree as ET
HERE = Path(__file__).resolve().parent
BASE = Path('/workspace/shared/peridot-global-base/selected_files/product/etc/displayconfig')
DONOR = Path('/workspace/shared/peridot-global-assembly/product-work/product/etc/displayconfig')

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def conditions(root):
    if not root.tag == 'thermal-brightness-config':
        raise ValueError("Validation failed: root.tag == 'thermal-brightness-config'")
    result = {}
    for node in root:
        if not node.tag == 'thermal-condition-item':
            raise ValueError("Validation failed: node.tag == 'thermal-condition-item'")
        identifier = int(node.findtext('identifier'))
        if not identifier not in result:
            raise ValueError('duplicate condition identifier')
        if not node.findtext('description'):
            raise ValueError('description is required')
        result[identifier] = node
    return result

def triples(node):
    result = []
    for pair in node.findall('temperature-brightness-pair'):
        if not [x.tag for x in pair] == ['min-inclusive', 'max-exclusive', 'nit']:
            raise ValueError("Validation failed: [x.tag for x in pair] == ['min-inclusive', 'max-exclusive', 'nit']")
        values = tuple((pair.findtext(x) for x in ['min-inclusive', 'max-exclusive', 'nit']))
        lo, hi, nit = map(float, values)
        if not (all((math.isfinite(x) for x in (lo, hi, nit))) and lo < hi and (nit > 0)):
            raise ValueError('Validation failed: all((math.isfinite(x) for x in (lo, hi, nit))) and lo < hi and (nit > 0)')
        if result:
            if not float(result[-1][1]) == lo:
                raise ValueError('non-contiguous or overlapping temperature pairs')
        result.append(values)
    if not result:
        raise ValueError('empty temperature table')
    return result

def select_lux(condition, lux):
    highest = None
    for pair in condition.findall('lux-temperature-pair'):
        lo, hi = (float(pair.findtext('min-inclusive')), float(pair.findtext('max-exclusive')))
        if lux >= lo and lux < hi:
            return pair
        if highest is None or hi > float(highest.findtext('max-exclusive')):
            highest = pair
    if highest is not None and lux >= float(highest.findtext('max-exclusive')):
        return highest
    return None

def select_temp(pairs, temp):
    for lo, hi, nit in pairs:
        if temp >= float(lo) and temp < float(hi):
            return float(nit)
    return None

def main():
    classic_path = BASE / 'thermal_brightness_control.xml'
    common_path = BASE / 'common_multi_factor_thermal_brightness_control.xml'
    donor_common_path = DONOR / common_path.name
    if not sha(classic_path) == 'b42896fff6942616d116744b7c5291e21949b673de395a5c056e58ab848cf694':
        raise ValueError('unexpected classic source bytes')
    if not sha(common_path) == 'a8a0f20094366aa998ccff432370bb95bcffbf7126d6126b82f6fbd09c39e470':
        raise ValueError('unexpected common source bytes')
    if not sha(common_path) == sha(donor_common_path):
        raise ValueError('common config differs between verified sources')
    classic = conditions(ET.parse(classic_path).getroot())
    common = conditions(ET.parse(common_path).getroot())
    if not list(classic) == [0, 10, 18, 700, 20, -2]:
        raise ValueError('Validation failed: list(classic) == [0, 10, 18, 700, 20, -2]')
    if not (-3 in common and -3 not in classic):
        raise ValueError('Validation failed: -3 in common and -3 not in classic')
    if not common[-3].findtext('description') == 'NTC':
        raise ValueError("Validation failed: common[-3].findtext('description') == 'NTC'")
    root = ET.Element('thermal-brightness-config')
    preserved = []
    for identifier, source in classic.items():
        if not [n.tag for n in source] == ['identifier', 'description'] + ['temperature-brightness-pair'] * len(source.findall('temperature-brightness-pair')):
            raise ValueError("Validation failed: [n.tag for n in source] == ['identifier', 'description'] + ['temperature-brightness-pair'] * len(source.findall('temperature-brightness-pair'))")
        original = triples(source)
        target = ET.SubElement(root, 'thermal-condition-item')
        target.append(copy.deepcopy(source.find('identifier')))
        target.append(copy.deepcopy(source.find('description')))
        lux = ET.SubElement(target, 'lux-temperature-pair')
        ET.SubElement(lux, 'min-inclusive').text = '0'
        ET.SubElement(lux, 'max-exclusive').text = '2000000'
        for pair in source.findall('temperature-brightness-pair'):
            lux.append(copy.deepcopy(pair))
        if not triples(lux) == original:
            raise ValueError('Validation failed: triples(lux) == original')
        preserved.append({'identifier': identifier, 'description': source.findtext('description'), 'pairs': original})
    root.append(copy.deepcopy(common[-3]))
    converted = conditions(root)
    if not set(converted) == set(classic) | {-3}:
        raise ValueError('Validation failed: set(converted) == set(classic) | {-3}')
    if not ET.tostring(converted[-3]) == ET.tostring(common[-3]):
        raise ValueError('Validation failed: ET.tostring(converted[-3]) == ET.tostring(common[-3])')
    tests = 0
    luxes = [0, 1e-06, 5500, 6000, 20000, 50000, 1999999.75, 2000000, 2000001, 10000000, 3.4028234663852886e+38]
    for identifier, source in classic.items():
        original = triples(source)
        temperatures = {-100.0, 0.0, 15.0, 100.0, 1000.0}
        for lo, hi, _ in original:
            lo, hi = (float(lo), float(hi))
            temperatures.update([lo, hi, lo - 0.0001, lo + 0.0001, hi - 0.0001, hi + 0.0001, (lo + hi) / 2])
        for lux in luxes:
            selected = select_lux(converted[identifier], lux)
            if not selected is not None:
                raise ValueError('Validation failed: selected is not None')
            for temp in sorted(temperatures):
                if not select_temp(original, temp) == select_temp(triples(selected), temp):
                    raise ValueError('Validation failed: select_temp(original, temp) == select_temp(triples(selected), temp)')
                tests += 1
        if not select_lux(converted[identifier], -1) is None:
            raise ValueError('Validation failed: select_lux(converted[identifier], -1) is None')
        if not select_lux(converted[identifier], float('nan')) is None:
            raise ValueError("Validation failed: select_lux(converted[identifier], float('nan')) is None")
    for lux in luxes:
        if not triples(select_lux(converted[-3], lux)) == triples(select_lux(common[-3], lux)):
            raise ValueError('Validation failed: triples(select_lux(converted[-3], lux)) == triples(select_lux(common[-3], lux))')
    ET.indent(root, space='    ')
    output = HERE / 'proposed_multi_factor_thermal_brightness_control.xml'
    ET.ElementTree(root).write(output, encoding='utf-8', xml_declaration=True)
    if not conditions(ET.parse(output).getroot()).keys() == converted.keys():
        raise ValueError('Validation failed: conditions(ET.parse(output).getroot()).keys() == converted.keys()')
    report = {'scope': 'offline generated review artifact only; not applied to product', 'source_sha256': {str(p): sha(p) for p in [classic_path, common_path, donor_common_path]}, 'output': str(output), 'output_sha256': sha(output), 'preserved_classic_conditions': preserved, 'added_stock_identical_common_condition': -3, 'output_condition_ids': list(converted), 'temperature_lux_comparisons_passed': tests, 'lux_test_values': luxes, 'predicate': 'For each original F6 condition and finite L>=0, donor table lookup returns the unchanged F6 scalar nit limit or the same no-match result at every tested temperature and, by interval identity, throughout each original interval.', 'consumer_evidence': 'consumer-references.json: ThermalBrightnessController.getTemperatureBrightnessPairs, updateAmbientLuxThreshold, updateMaxThermalBrightness, loadConfigFromFile, loadThermalConfig, updateMaxNtcTempBrightness, updateThermalBrightnessIfNeeded', 'selection_semantics': 'Cloud config is attempted first, then local, then common. First successfully parsed config replaces the complete condition list. No merge with common occurs at runtime.', 'remaining_runtime_gates': ['Negative and NaN ambient lux select no bucket; prove they cannot reach this path after initialization before claiming whole-runtime equivalence.', 'Temperature below the first threshold and >=100 Celsius has no scalar table match in both original F6 data and converted data; shutdown, sensor validity and vendor thermal protection must remain intact.', 'Persisted cloud thermal config has precedence over product local config; offline review cannot determine or change device /data state.', 'NTC limiter is additionally guarded by config_thermal_brt_control_ntc_available and persist.vendor.ntc.flag; presence of condition -3 alone does not prove activation.', 'Exact F6 MiuiFrameworkResOverlay has main thermal limiter=true but does not override NTC availability. Retaining F6 baseline can therefore leave the donor NTC branch inactive; this is not evidence of weakening any F6 stock protection.', 'The IPA branch can select a different power-based limit for conditions710/711 if thermal_system_IPA_enabled. The exact target feature flag must be checked.', 'Consumer startup, JNI/sysfs sensor events, thermal-service compatibility and actual panel mapping remain untested; this test proves schema/scalar-table preservation only.', 'Donor product overlays still contain donor brightness and sensor calibration. No overlay transplantation is justified by this conversion alone.']}
    (HERE / 'thermal-conversion-validation.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'result': 'PASS', 'comparisons': tests, 'output_sha256': sha(output), 'conditions': list(converted)}, indent=2))
if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='Create and validate a review-only F6 thermal schema conversion; does not modify a ROM tree')
    parser.add_argument('--base-displayconfig', type=Path, default=BASE)
    parser.add_argument('--donor-displayconfig', type=Path, default=DONOR)
    parser.add_argument('--out-dir', type=Path, default=HERE)
    args = parser.parse_args()
    BASE = args.base_displayconfig.resolve()
    DONOR = args.donor_displayconfig.resolve()
    HERE = args.out_dir.resolve()
    if HERE in [BASE, DONOR] or BASE in HERE.parents or DONOR in HERE.parents:
        raise ValueError('Review output must be outside both source displayconfig directories')
    HERE.mkdir(parents=True, exist_ok=True)
    main()
