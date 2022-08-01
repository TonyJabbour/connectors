# coding: utf-8

import datetime
import re

# Importing the JSON module
import json
import sys

# Umporting the STIX module
import stix2
from pycti import Identity, Vulnerability, Label

def write_OR(name, cves):
    try:
        result_cpe = 'OR{\n'
        raw_cpe = ''
        for cpe in cves["cpe_match"]:
            vulnerable = cpe["vulnerable"]
            cpe23Uri = cpe["cpe23Uri"]
            raw_cpe = raw_cpe + cpe23Uri
            result_cpe = result_cpe + cpe23Uri + ' | vulnerable : ' + str(vulnerable) + ' | '
            versionStartIncluding = (cpe["versionStartIncluding"]
                if "versionStartIncluding" in cpe
                else None)
            if versionStartIncluding != None:
                result_cpe = result_cpe + 'versionStartIncluding : ' + versionStartIncluding + ' | '
                raw_cpe = raw_cpe + ' | ' + 'versionStartIncluding : ' + versionStartIncluding
            versionEndIncluding = (cpe["versionEndIncluding"]
                if "versionEndIncluding" in cpe
                else None)
            if versionEndIncluding != None:
                result_cpe = result_cpe + 'versionEndIncluding : ' + versionEndIncluding + ' | '
                raw_cpe = raw_cpe + ' | ' + 'versionEndIncluding : ' + versionEndIncluding 
            versionStartExcluding = (cpe["versionStartExcluding"]
                if "versionStartExcluding" in cpe
                else None)
            if versionStartExcluding != None:
                result_cpe = result_cpe + 'versionStartExcluding : ' + versionStartExcluding + ' | '
                raw_cpe = raw_cpe + ' | ' + 'versionStartExcluding : ' + versionStartExcluding
            versionEndExcluding = (cpe["versionEndExcluding"]
                if "versionEndExcluding" in cpe
                else None)
            if versionEndExcluding != None:
                result_cpe = result_cpe + 'versionEndExcluding : ' + versionEndExcluding + ' | '
                raw_cpe = raw_cpe + ' | ' + 'versionEndExcluding : ' + versionEndExcluding 
            raw_cpe = raw_cpe + ','
            result_cpe = result_cpe[:-2] + '\n'
        result_cpe = result_cpe + '}\n'
        return result_cpe, raw_cpe
    except Exception as e:
        print("Error with " + name + " - " + str(e))

def write_AND_OR(name, cves):
    try:
        result_cpe = 'AND{\n'
        raw_cpe = ''
        for sub_conf in cves["children"]:
            result_cpe = result_cpe + sub_conf["operator"] + '{\n'
            for cpe in sub_conf["cpe_match"]:
                vulnerable = cpe["vulnerable"]
                cpe23Uri = cpe["cpe23Uri"]
                raw_cpe = raw_cpe + cpe23Uri
                result_cpe = result_cpe + cpe23Uri + ' | vulnerable : ' + str(vulnerable) + ' | '
                versionStartIncluding = (cpe["versionStartIncluding"]
                    if "versionStartIncluding" in cpe
                    else None)
                if versionStartIncluding != None:
                    result_cpe = result_cpe + 'versionStartIncluding : ' + versionStartIncluding + ' | '
                    raw_cpe = raw_cpe + ' | ' + 'versionStartIncluding : ' + versionStartIncluding
                versionEndIncluding = (cpe["versionEndIncluding"]
                    if "versionEndIncluding" in cpe
                    else None)
                if versionEndIncluding != None:
                    result_cpe = result_cpe + 'versionEndIncluding : ' + versionEndIncluding + ' | '
                    raw_cpe = raw_cpe + ' | ' + 'versionEndIncluding : ' + versionEndIncluding 
                versionStartExcluding = (cpe["versionStartExcluding"]
                    if "versionStartExcluding" in cpe
                    else None)
                if versionStartExcluding != None:
                    result_cpe = result_cpe + 'versionStartExcluding : ' + versionStartExcluding + ' | '
                    raw_cpe = raw_cpe + ' | ' + 'versionStartExcluding : ' + versionStartExcluding 
                versionEndExcluding = (cpe["versionEndExcluding"]
                    if "versionEndExcluding" in cpe
                    else None)
                if versionEndExcluding != None:
                    result_cpe = result_cpe + 'versionEndExcluding : ' + versionEndExcluding + ' | '
                    raw_cpe = raw_cpe + ' | ' + 'versionEndExcluding : ' + versionEndExcluding
                raw_cpe = raw_cpe + ','
                result_cpe = result_cpe[:-2] + '\n'
            result_cpe = result_cpe + '}\n'
        result_cpe = result_cpe + '}\n'
        return result_cpe, raw_cpe
    except Exception as e:
        print("Error with " + name + " - " + str(e))

def write_AND(name, cves):
    try:
        result_cpe = 'AND{\n'
        raw_cpe = ''
        for cpe in cves["cpe_match"]:
            vulnerable = cpe["vulnerable"]
            cpe23Uri = cpe["cpe23Uri"]
            raw_cpe = raw_cpe + cpe23Uri
            result_cpe = result_cpe + cpe23Uri + ' | vulnerable : ' + str(vulnerable) + ' | '
            versionStartIncluding = (cpe["versionStartIncluding"]
                if "versionStartIncluding" in cpe
                else None)
            if versionStartIncluding != None:
                result_cpe = result_cpe + 'versionStartIncluding : ' + versionStartIncluding + ' | '
                raw_cpe = raw_cpe + ' | ' + 'versionStartIncluding : ' + versionStartIncluding 
            versionEndIncluding = (cpe["versionEndIncluding"]
                if "versionEndIncluding" in cpe
                else None)
            if versionEndIncluding != None:
                result_cpe = result_cpe + 'versionEndIncluding : ' + versionEndIncluding + ' | '
                raw_cpe = raw_cpe + ' | ' + 'versionEndIncluding : ' + versionEndIncluding 
            versionStartExcluding = (cpe["versionStartExcluding"]
                if "versionStartExcluding" in cpe
                else None)
            if versionStartExcluding != None:
                result_cpe = result_cpe + 'versionStartExcluding : ' + versionStartExcluding + ' | '
                raw_cpe = raw_cpe + ' | ' + 'versionStartExcluding : ' + versionStartExcluding
            versionEndExcluding = (cpe["versionEndExcluding"]
                if "versionEndExcluding" in cpe
                else None)
            if versionEndExcluding != None:
                result_cpe = result_cpe + 'versionEndExcluding : ' + versionEndExcluding + ' | '
                raw_cpe = raw_cpe + ' | ' + 'versionEndExcluding : ' + versionEndExcluding 
            raw_cpe = raw_cpe + ','
            result_cpe = result_cpe[:-2] + '\n'
        result_cpe = result_cpe + '}\n'
        return result_cpe, raw_cpe
    except Exception as e:
        print("Error with " + name + " - " + str(e))

def convert(filename, output="output.json"):
    # Create the default author
    author = stix2.Identity(
        id=Identity.generate_id("The MITRE Corporation", "organization"),
        name="The MITRE Corporation",
        identity_class="organization",
    )
    added_CVE = []
    with open(filename) as json_file:
        vulnerabilities_bundle = [author]
        data = json.load(json_file)
        for cves in data["CVE_Items"]:
            # Get the name
            name = cves["cve"]["CVE_data_meta"]["ID"]
            # Create external references
            external_reference = stix2.ExternalReference(
                source_name="NIST NVD", url="https://nvd.nist.gov/vuln/detail/" + name
            )
            external_references = [external_reference]
            if (
                "references" in cves["cve"]
                and "reference_data" in cves["cve"]["references"]
            ):
                for reference in cves["cve"]["references"]["reference_data"]:
                    external_reference = stix2.ExternalReference(
                        source_name=reference["refsource"], url=reference["url"]
                    )
                    external_references.append(external_reference)
	    
            # Check if CWE and add in the references
            if (
                "problemtype_data" in cves["cve"]["problemtype"] 
                and "description" in cves["cve"]["problemtype"]["problemtype_data"][0]
            ):
                cwe = ''
                for value in cves["cve"]["problemtype"]["problemtype_data"][0]["description"]:
                    cwe = cwe + value["value"] + ", "
                    try:
                        external_reference_cwe = stix2.ExternalReference(
                            source_name="MITRE", url="https://cwe.mitre.org/data/definitions/" + 
                            re.findall(r'\d+',value["value"])[0] + ".html")
                        external_references.append(external_reference_cwe)  
                    except:
                        ("Error in the CWE-value : " + value["value"])
                cwe = cwe[:-2]
            else :
                cwe = None
            
            # CPE extraction
            cpe = ''
            raw_cpe = ''
            for parent_conf in cves["configurations"]["nodes"]:
                try:
                    if(parent_conf["operator"] == 'OR'):
                        cpe_temp, raw_cpe_temp = write_OR(name, parent_conf)
                    elif(parent_conf["operator"] == 'AND' and len(parent_conf["children"]) == 0):
                        cpe_temp, raw_cpe_temp = write_AND(name, parent_conf)
                    elif(parent_conf["operator"] == 'AND' and len(parent_conf["children"]) > 0):
                        cpe_temp, raw_cpe_temp = write_AND_OR(name, parent_conf)
                    cpe = cpe + cpe_temp
                    raw_cpe = raw_cpe + raw_cpe_temp
                except:
                    ("Error in the CPE-value : " + name)
            if(len(raw_cpe) > 1):
                raw_cpe = raw_cpe[:-1]
            
            # Getting the different fields
            description = cves["cve"]["description"]["description_data"][0]["value"]
            base_score = (
                cves["impact"]["baseMetricV3"]["cvssV3"]["baseScore"]
                if "baseMetricV3" in cves["impact"]
                else None
            )
            base_severity = (
                cves["impact"]["baseMetricV3"]["cvssV3"]["baseSeverity"]
                if "baseMetricV3" in cves["impact"]
                else None
            )
            attack_vector = (
                cves["impact"]["baseMetricV3"]["cvssV3"]["attackVector"]
                if "baseMetricV3" in cves["impact"]
                else None
            )
            integrity_impact = (
                cves["impact"]["baseMetricV3"]["cvssV3"]["integrityImpact"]
                if "baseMetricV3" in cves["impact"]
                else None
            )
            availability_impact = (
                cves["impact"]["baseMetricV3"]["cvssV3"]["availabilityImpact"]
                if "baseMetricV3" in cves["impact"]
                else None
            )
            confidentiality_impact = (
                cves["impact"]["baseMetricV3"]["cvssV3"]["confidentialityImpact"]
                if "baseMetricV3" in cves["impact"]
                else None
            )
            cdate = datetime.datetime.strptime(cves["publishedDate"], "%Y-%m-%dT%H:%MZ")
            mdate = datetime.datetime.strptime(
                cves["lastModifiedDate"], "%Y-%m-%dT%H:%MZ"
            )
            

            # Creating the vulnerability with the extracted fields
            vuln = stix2.Vulnerability(
                id=Vulnerability.generate_id(name),
                name=name,
                created=cdate,
                modified=mdate,
                description=description,
                created_by_ref=author,
                external_references=external_references,
                custom_properties={
                    "x_opencti_base_score": base_score,
                    "x_opencti_base_severity": base_severity,
                    "x_opencti_attack_vector": attack_vector,
                    "x_opencti_integrity_impact": integrity_impact,
                    "x_opencti_availability_impact": availability_impact,
                    "x_opencti_confidentiality_impact": confidentiality_impact,
                    "x_opencti_cwe": cwe,
                    "x_opencti_raw_cpe": raw_cpe,
                    "x_opencti_related_cpe": None,
                    "x_opencti_cpe": cpe,
                },
            )
            added_CVE.append([Vulnerability.generate_id(name),name,raw_cpe])
            # Adding the vulnerability to the list of vulnerabilities
            vulnerabilities_bundle.append(vuln)
    # Creating the bundle from the list of vulnerabilities
    bundle = stix2.Bundle(vulnerabilities_bundle, allow_custom=True)
    bundle_json = bundle.serialize()
    # Write to file
    with open(output, "w") as f:
        f.write(bundle_json)
    return added_CVE


if __name__ == "__main__":
    convert(sys.argv[1], sys.argv[2])
