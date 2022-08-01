# coding: utf-8

import datetime

# Importing the JSON module
import xml.etree.ElementTree as et
import sys

# Umporting the STIX module
import stix2
from pycti import Identity, AttackPattern


def convert(filename, output="output.json"):
    # Create the default author
    author = stix2.Identity(
        id=Identity.generate_id("The MITRE Corporation", "organization"),
        name="The MITRE Corporation",
        identity_class="organization",
    )
    with open(filename) as xml_file:
        attackpattern_bundle = [author]
        tree = et.parse(xml_file)
        root = tree.getroot()
        if root.findall('{http://cwe.mitre.org/cwe-6}Weaknesses'):
            weaknesses = root.find('{http://cwe.mitre.org/cwe-6}Weaknesses')
            for weakness in weaknesses:
                # Get the weakness ID
                weakness_id = weakness.get("ID")
                
                # Get the weakness name
                weakness_name = weakness.get("Name")
                
                # Get the weakness description
                weakness_descr = ''
                # Detailed description is preferred over description
                if weakness.find("{http://cwe.mitre.org/cwe-6}Extended_Description") is not None:
                    extend_descr = weakness.iter("{http://cwe.mitre.org/cwe-6}Extended_Description")
                    for child in extend_descr:
                        for elem in child.iter():
                        # Takes into account all formating
                            if elem.tag == "{http://cwe.mitre.org/cwe-6}Extended_Description" or elem.tag == "{http://www.w3.org/1999/xhtml}p" or elem.tag == "{http://www.w3.org/1999/xhtml}li":
                                if elem.text:
                                    weakness_descr = weakness_descr + elem.text.strip() + "\n"
                    weakness_descr = weakness_descr[:-1]
                #url_weakness_descr = "https://cwe.mitre.org/data/definitions/" + weakness_id + ".html#Extended_Description"
                else:
                    weakness_descr = weakness.find("{http://cwe.mitre.org/cwe-6}Description").text
                    #url_weakness_descr = "https://cwe.mitre.org/data/definitions/" + weakness_id + ".html#Description"
                # If void -> None
                if weakness_descr == "":
                    weakness_descr = "-"
                            
                # Get the related weaknesses
                related_weakness_type_id = ""
                if weakness.find("{http://cwe.mitre.org/cwe-6}Related_Weaknesses"):
                    related_weakness = weakness.find("{http://cwe.mitre.org/cwe-6}Related_Weaknesses")
                    for child in related_weakness:
                        related_weakness_type = child.get("Nature")
                        related_weakness_id = child.get("CWE_ID")
                        related_weakness_type_id = related_weakness_type_id + related_weakness_type + "=>" + related_weakness_id + " ; "
                    related_weakness_type_id = related_weakness_type_id[:-3]
                # If void -> None
                if related_weakness_type_id == "":
                    related_weakness_type_id = "-"
                
                # Get the modes of introduction
                index = 0
                modes_intro_weakness_text = "Modes of introduction :"
                modes_intro_weakness = weakness.iter("{http://cwe.mitre.org/cwe-6}Modes_Of_Introduction")
                for child in modes_intro_weakness:
                    for elem in child.iter():
                        # Different cases of formatting
                        if elem.tag == "{http://cwe.mitre.org/cwe-6}Introduction":
                            index = index + 1
                            modes_intro_weakness_text = modes_intro_weakness_text + "\n===" + str(index) + "===\n"
                        if elem.tag == "{http://cwe.mitre.org/cwe-6}Phase":
                            if elem.text and elem.text.strip():
                                modes_intro_weakness_text = modes_intro_weakness_text + "[phase] " + elem.text + "\n"
                        if elem.tag == "{http://www.w3.org/1999/xhtml}p":
                            if elem.text and elem.text.strip():
                                modes_intro_weakness_text = modes_intro_weakness_text + "[note] " + elem.text + "\n"
                        elif elem.tag == "{http://cwe.mitre.org/cwe-6}Note":
                            if elem.text and elem.text.strip():
                                modes_intro_weakness_text = modes_intro_weakness_text + "[note] " + elem.text + "\n"
                modes_intro_weakness_text = modes_intro_weakness_text[:-1]
                if(modes_intro_weakness_text == "Modes of introduction "):
                    modes_intro_weakness_text = "-"
                
                # Get the likelihood of exploit
                weakness_exploit_likelihood = ""
                if weakness.find("{http://cwe.mitre.org/cwe-6}Likelihood_Of_Exploit") is not None:
                    weakness_exploit_likelihood = weakness.find("{http://cwe.mitre.org/cwe-6}Likelihood_Of_Exploit").text
                #weakness_exploit_likelihood = "https://cwe.mitre.org/data/definitions/" + weakness_id + ".html#Likelihood_Of_Exploit"
                # If void -> None
                if weakness_exploit_likelihood == "":
                    weakness_exploit_likelihood = "-"
                    
                # Get the common consequences
                index = 0
                common_consequences_scope = "Common Consequences :"
                common_consequences = weakness.iter("{http://cwe.mitre.org/cwe-6}Common_Consequences")
                for child in common_consequences:
                    for elem in child.iter():
                        # Different cases of formatting
                        if elem.tag == "{http://cwe.mitre.org/cwe-6}Consequence":
                            index = index + 1
                            common_consequences_scope = common_consequences_scope + "\n===" + str(index) + "===\n"
                        if elem.tag == "{http://cwe.mitre.org/cwe-6}Scope":
                            if elem.text and elem.text.strip():
                                common_consequences_scope = common_consequences_scope + "[scope] " + elem.text + "\n"
                        if elem.tag == "{http://cwe.mitre.org/cwe-6}Impact":
                            if elem.text and elem.text.strip():
                                common_consequences_scope = common_consequences_scope + "[impact] " + elem.text + "\n"
                        if elem.tag == "{http://www.w3.org/1999/xhtml}p":
                            if elem.text and elem.text.strip():
                                common_consequences_scope = common_consequences_scope + "[note] " + elem.text + "\n"
                        elif elem.tag == "{http://cwe.mitre.org/cwe-6}Note":
                            if elem.text and elem.text.strip():
                                common_consequences_scope = common_consequences_scope + "[note] " + elem.text + "\n"
                common_consequences_scope = common_consequences_scope[:-1]
                if(common_consequences_scope == "Common Consequences "):
                    common_consequences_scope = "-"
                
                # Get the detection methods    
                index = 0
                detection_methods_description = "Detection methods :"
                detection_methods = weakness.iter("{http://cwe.mitre.org/cwe-6}Detection_Methods")
                for child in detection_methods:
                    for elem in child.iter():
                        if elem.tag == "{http://cwe.mitre.org/cwe-6}Detection_Method":
                            index = index + 1
                            detection_methods_description = detection_methods_description + "\n===" + str(index) + "===\n"
                        if elem.tag == "{http://cwe.mitre.org/cwe-6}Method":
                            if elem.text and elem.text.strip():
                                detection_methods_description = detection_methods_description + "[method] " + elem.text + "\n"
                        if elem.tag == "{http://cwe.mitre.org/cwe-6}Effectiveness_Notes" or elem.tag == "{http://cwe.mitre.org/cwe-6}Effectiveness":
                            if elem.text and elem.text.strip():
                                detection_methods_description = detection_methods_description + "[effectiveness] " + elem.text + "\n"
                        if elem.tag == "{http://www.w3.org/1999/xhtml}li":
                            if elem.text and elem.text.strip():
                                detection_methods_description = detection_methods_description + "[description] " + elem.text + "\n"
                        elif elem.tag == "{http://www.w3.org/1999/xhtml}div":
                            if elem.text and elem.text.strip():
                                detection_methods_description = detection_methods_description + "[description] " + elem.text + "\n"
                        elif elem.tag == "{http://www.w3.org/1999/xhtml}p":
                            if elem.text and elem.text.strip():
                                detection_methods_description = detection_methods_description + "[description] " + elem.text + "\n"
                        elif elem.tag == "{http://cwe.mitre.org/cwe-6}Description":
                            if elem.text and elem.text.strip():
                                detection_methods_description = detection_methods_description + "[description] " + elem.text + "\n"
                detection_methods_description = detection_methods_description[:-1]
                if(detection_methods_description == "Detection methods "):
                    detection_methods_description = "-"

                # Get the potential mitigations
                index = 0
                potential_mitigations_description = "Potential mitigations :"
                potential_mitigations = weakness.iter("{http://cwe.mitre.org/cwe-6}Potential_Mitigations")
                for child in potential_mitigations:
                    for elem in child.iter():
                        if elem.tag == "{http://cwe.mitre.org/cwe-6}Mitigation":
                            index = index + 1
                            potential_mitigations_description = potential_mitigations_description + "\n===" + str(index) + "===\n"
                        if elem.tag == "{http://cwe.mitre.org/cwe-6}Phase":
                            if elem.text and elem.text.strip():
                                potential_mitigations_description = potential_mitigations_description + "[phase] " + elem.text + "\n"
                        if elem.tag == "{http://cwe.mitre.org/cwe-6}Strategy":
                            if elem.text and elem.text.strip():
                                potential_mitigations_description = potential_mitigations_description + "[strategy] " + elem.text + "\n"
                        if elem.tag == "{http://cwe.mitre.org/cwe-6}Effectiveness_Notes" or elem.tag == "{http://cwe.mitre.org/cwe-6}Effectiveness":
                            if elem.text and elem.text.strip():
                                potential_mitigations_description = potential_mitigations_description + "[effectiveness] " + elem.text + "\n"
                        if elem.tag == "{http://www.w3.org/1999/xhtml}p":
                            if elem.text and elem.text.strip():
                                potential_mitigations_description = potential_mitigations_description + "[description] " + elem.text + "\n"
                        elif elem.tag == "{http://cwe.mitre.org/cwe-6}Description":
                            if elem.text and elem.text.strip():
                                potential_mitigations_description = potential_mitigations_description + "[description] " + elem.text + "\n"
                potential_mitigations_description = potential_mitigations_description[:-1]
                if(potential_mitigations_description == "Potential mitigations "):
                    potential_mitigations_description = "-"
                
                # Get the demonstrative exemples 
                index = 0
                demonstrative_exemples = ''
                demonstrative_exemples_present = weakness.iter("{http://cwe.mitre.org/cwe-6}Demonstrative_Examples")
                for child in demonstrative_exemples_present:
                    for elem in child.iter():
                        if elem.tag == "{http://cwe.mitre.org/cwe-6}Demonstrative_Example":
                            index = index + 1
                if(index > 0):
                    demonstrative_exemples = "YES : " + str(index) + " example(s)."
                else:
                    demonstrative_exemples = "NO : " + str(index) + " example."
                #url_demonstrative_exemples = "https://cwe.mitre.org/data/definitions/" + weakness_id + ".html#Demonstrative_Examples"

                # Get the different dates
                submission_date = ""
                weakness.find("{http://cwe.mitre.org/cwe-6}Content_History")
                history_date = weakness.find("{http://cwe.mitre.org/cwe-6}Content_History")
                submission = history_date.find("{http://cwe.mitre.org/cwe-6}Submission")
                submission_date = submission.find("{http://cwe.mitre.org/cwe-6}Submission_Date").text
                # If void -> None
                if submission_date == "":
                    submission_date = None
                else:
                    submission_date = datetime.datetime.strptime(submission_date, "%Y-%m-%d")
                    
                # Create external references
                external_reference = stix2.ExternalReference(
                    source_name="MITRE", url="https://cwe.mitre.org/data/definitions/" + weakness_id + ".html"
                )
                external_references = [external_reference]

                # Creating the attack pattern with the extracted fields
                attack_pattern = stix2.AttackPattern(
                    id=AttackPattern.generate_id(weakness_name),
                    name="CWE-" + weakness_id,
                    created=submission_date,
                    description=weakness_name + " :\n" + weakness_descr,
                    created_by_ref=author,
                    aliases=weakness_name,
                    external_references=external_references,
                    custom_properties={
                        "x_opencti_cwe_id": weakness_id,
                        "x_opencti_cwe_related_weaknesses": related_weakness_type_id,
                        "x_opencti_cwe_modes_introduction_text": modes_intro_weakness_text,
                        "x_opencti_cwe_exploit_likelihood": weakness_exploit_likelihood,
                        "x_opencti_cwe_common_consequences_scope": common_consequences_scope,
                        "x_opencti_cwe_detection_methods_description": detection_methods_description,
                        "x_opencti_cwe_potential_mitigations_description": potential_mitigations_description,
                        "x_opencti_cwe_demonstrative_exemples": demonstrative_exemples,
                    },
                ) 
                # Adding the attack pattern to the list of attack patterns
                attackpattern_bundle.append(attack_pattern)
        # Creating the bundle from the list of attack patterns
        bundle = stix2.Bundle(attackpattern_bundle, allow_custom=True)
        bundle_json = bundle.serialize()
        # Write to file
        with open(output, "w") as f:
            f.write(bundle_json)
        f.close()
    xml_file.close()


if __name__ == "__main__":
    convert(sys.argv[1], sys.argv[2])
