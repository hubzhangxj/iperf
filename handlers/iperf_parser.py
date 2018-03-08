#!/usr/bin/env python
# -*- coding:utf-8 -*-

import re
import string
import copy
import json
from caliper.server.parser_process import parser_log

def iperf_parser(content, outfp, tag):
    score = -1
    sum_score = 0
    count = 0
    if (tag == 'iperf TCP'):
        if re.search('SUM', content):
            for speed in re.findall("\[SUM\].*?[MG]Bytes(.*?)MBytes/sec.*?sender", content):
                score = string.atof(speed.strip())
        else:
            for speed in re.findall("[MG]Bytes(.*?)MBytes/sec.*?sender", content):
                score = string.atof(speed.strip())
    else:
        if (tag == 'iperf UDP'):
            if re.search('SUM', content):
                for speed in re.findall("\[SUM\].*?[MG]Bytes(.*?)MBytes/sec.*?/.*?", content):
                    score = string.atof(speed.strip())
            else:
                for speed in re.findall("[MG]Bytes(.*?)MBytes/sec.*?/.*?", content):
                    score = string.atof(speed.strip())

    outfp.write("speed of %s is %.3f MBytes/sec\n" % (tag, score))

    return score * 8

def iperf_TCP_parser(content, outfp):
    return iperf_parser(content, outfp, 'iperf TCP')

def iperf_UDP_parser(content, outfp):
    return iperf_parser(content, outfp, 'iperf UDP')

def iperf(filePath, outfp):
    cases = parser_log.parseData(filePath)
    result = []
    for case in cases:
        caseDict = {}
        caseDict[parser_log.BOTTOM] = parser_log.getBottom(case)
        titleGroup = re.search("\[test:([\s\S]+?)\]", case)
        testcase = ""
        if titleGroup != None:
            testcase = titleGroup.groups()[0].strip()
            caseDict[parser_log.TOP] = titleGroup.group(0)

        tables = []
        tableContent = {}
        if testcase == "iperf TCP_sin_1_tx" or testcase == "iperf TCP_sin_1_rx":
            center_top = re.search("Connecting[\s\S]+?\n", case)
            if center_top is not None:
                tableContent[parser_log.CENTER_TOP] = center_top.group(0)
            tc = re.search("(\[ ID\][\s\S]+\n)(- ){3,}", case)
            if tc is not None:
                content = re.sub("\(omitted\)|\[|\]", "", tc.groups()[0])
                merges = [[2, 3], [4, 5], [6, 7], [9, 10]]
                tableContent[parser_log.TABLE] = parser_log.parseMergeTable(content, "\\s{1,}", merges, [1])
                tables.append(copy.deepcopy(tableContent))

            tc = re.search("- - -\n(\[ ID\][\s\S]+\n)[\n\r]{1,}", case)
            if tc is not None:
                content = re.sub("\(omitted\)|\[|\]", "", tc.groups()[0])
                merges = [[2, 3], [4, 5], [6, 7]]
                tableContent[parser_log.TABLE] = parser_log.parseMergeTable(content, "\\s{1,}", merges, [1], [[1, 6], [3, 5]])
                tableContent[parser_log.CENTER_TOP] = ""
                tables.append(copy.deepcopy(tableContent))
        if testcase == "iperf TCP_sin_3_tx" or testcase == "iperf TCP_sin_3_rx":
            center_top = re.search("Connecting[\s\S]+?\n", case)
            if center_top is not None:
                tableContent[parser_log.CENTER_TOP] = center_top.group(0)
            tc = re.search("(\[ ID\][\s\S]+?\n)(- ){3,}", case)
            if tc is not None:
                content = re.sub("\(omitted\)|\[|\]", "", tc.groups()[0])
                merges = [[2, 3], [4, 5], [6, 7], [9, 10]]
                tableContent[parser_log.TABLE] = parser_log.parseMergeTable(content, "\\s{1,}", merges, [1], [[5, 6]])
                tables.append(copy.deepcopy(tableContent))
            split_content = re.sub("\[  4\][\s\S]+?\[  8\][\s\S]+?\n", "", case, 1)
            tc_groups = re.findall("(\[  4\][\s\S]+?\n\[SUM\][\s\S]+?\n)- - -", split_content)
            for tc in tc_groups:
                content = re.sub("\(omitted\)|\[|\]", "", tc)
                merges = [[2, 3], [4, 5], [6, 7], [9, 10]]
                tableContent[parser_log.TABLE] = ""
                tableContent[parser_log.I_TABLE] = parser_log.parseMergeTable(content, "\\s{1,}", merges, adds=[[4, 6]])
                tableContent[parser_log.CENTER_TOP] = ""
                tables.append(copy.deepcopy(tableContent))
            nowContent = re.sub("(\[ ID\][\s\S]+?\n)(- ){3,}", "", split_content)
            tc_groups = re.search("(\[ ID\] [\s\S]+\n\[SUM\][\s\S]+?\n)", nowContent)
            if tc_groups is not None:
                content = re.sub("\(omitted\)|\[|\]", "", tc_groups.groups()[0])
                merges = [[2, 3], [4, 5], [6, 7]]
                tableContent[parser_log.TABLE] = ""
                tableContent[parser_log.I_TABLE] = parser_log.parseMergeTable(content, "\\s{1,}", merges, [1],
                                                                  adds=[[3, 5], [5, 5], [7, 5], [9, 5]])
                tableContent[parser_log.CENTER_TOP] = ""
                tables.append(copy.deepcopy(tableContent))

        if testcase == "iperf TCP_sin_4_tx" or testcase == "iperf TCP_sin_4_rx":
            center_top = re.search("Connecting[\s\S]+?\n", case)
            if center_top is not None:
                tableContent[parser_log.CENTER_TOP] = center_top.group(0)
            tc = re.search("(\[ ID\][\s\S]+?\n)(- ){3,}", case)
            if tc is not None:
                content = re.sub("\(omitted\)|\[|\]", "", tc.groups()[0])
                merges = [[2, 3], [4, 5], [6, 7], [9, 10]]
                tableContent[parser_log.TABLE] = parser_log.parseMergeTable(content, "\\s{1,}", merges, [1], [[6, 6]])
                tables.append(copy.deepcopy(tableContent))
            split_content = re.sub("\[  4\][\s\S]+?\[  8\][\s\S]+?\n", "", case, 1)
            tc_groups = re.findall("(\[  4\][\s\S]+?\n\[SUM\][\s\S]+?\n)- - -", split_content)
            for tc in tc_groups:
                content = re.sub("\(omitted\)|\[|\]", "", tc)
                merges = [[2, 3], [4, 5], [6, 7], [9, 10]]
                tableContent[parser_log.TABLE] = ""
                tableContent[parser_log.I_TABLE] = parser_log.parseMergeTable(content, "\\s{1,}", merges, adds=[[5, 6]])
                tableContent[parser_log.CENTER_TOP] = ""
                tables.append(copy.deepcopy(tableContent))
            nowContent = re.sub("(\[ ID\][\s\S]+?\n)(- ){3,}", "", split_content)
            tc_groups = re.search("(\[ ID\] [\s\S]+\n\[SUM\][\s\S]+?\n)", nowContent)
            if tc_groups is not None:
                content = re.sub("\(omitted\)|\[|\]", "", tc_groups.groups()[0])
                merges = [[2, 3], [4, 5], [6, 7]]
                tableContent[parser_log.TABLE] = ""
                tableContent[parser_log.I_TABLE] = parser_log.parseMergeTable(content, "\\s{1,}", merges, [1],
                                                                  adds=[[3, 5], [5, 5], [7, 5], [9, 5]])
                tableContent[parser_log.CENTER_TOP] = ""
                tables.append(copy.deepcopy(tableContent))

        if testcase == "iperf TCP_sin_5_tx" or testcase == "iperf TCP_sin_5_rx":
            center_top = re.search("Connecting[\s\S]+?\n", case)
            if center_top is not None:
                tableContent[parser_log.CENTER_TOP] = center_top.group(0)
            tc = re.search("(\[ ID\][\s\S]+?\n)(- ){3,}", case)
            if tc is not None:
                content = re.sub("\(omitted\)|\[|\]", "", tc.groups()[0])
                merges = [[2, 3], [4, 5], [6, 7], [9, 10]]
                tableContent[parser_log.TABLE] = parser_log.parseMergeTable(content, "\\s{1,}", merges, [1], [[7, 6]])
                tables.append(copy.deepcopy(tableContent))
            split_content = re.sub("\[  4\][\s\S]+?\[  8\][\s\S]+?\n", "", case, 1)
            tc_groups = re.findall("(\[  4\][\s\S]+?\n\[SUM\][\s\S]+?\n)- - -", split_content)
            for tc in tc_groups:
                content = re.sub("\(omitted\)|\[|\]", "", tc)
                merges = [[2, 3], [4, 5], [6, 7], [9, 10]]
                tableContent[parser_log.TABLE] = ""
                tableContent[parser_log.I_TABLE] = parser_log.parseMergeTable(content, "\\s{1,}", merges, adds=[[6, 6]])
                tableContent[parser_log.CENTER_TOP] = ""
                tables.append(copy.deepcopy(tableContent))
            nowContent = re.sub("(\[ ID\][\s\S]+?\n)(- ){3,}", "", split_content)
            tc_groups = re.search("(\[ ID\] [\s\S]+\n\[SUM\][\s\S]+?\n)", nowContent)
            if tc_groups is not None:
                content = re.sub("\(omitted\)|\[|\]", "", tc_groups.groups()[0])
                merges = [[2, 3], [4, 5], [6, 7]]
                tableContent[parser_log.TABLE] = ""
                tableContent[parser_log.I_TABLE] = parser_log.parseMergeTable(content, "\\s{1,}", merges, [1],
                                                                  adds=[[3, 5], [5, 5], [7, 5], [9, 5], [11, 5],
                                                                        [13, 5]])
                tableContent[parser_log.CENTER_TOP] = ""
                tables.append(copy.deepcopy(tableContent))
        if testcase == "iperf TCP_sin_10_tx" or testcase == "iperf TCP_sin_10_rx":
            center_top = re.search("Connecting[\s\S]+?\n", case)
            if center_top is not None:
                tableContent[parser_log.CENTER_TOP] = center_top.group(0)
            tc = re.search("(\[ ID\][\s\S]+?\n)(- ){3,}", case)
            if tc is not None:
                content = re.sub("\(omitted\)|\[|\]", "", tc.groups()[0])
                merges = [[2, 3], [4, 5], [6, 7], [9, 10]]
                tableContent[parser_log.TABLE] = parser_log.parseMergeTable(content, "\\s{1,}", merges, [1], [[12, 6]])
                tables.append(copy.deepcopy(tableContent))
            split_content = re.sub("\[  4\][\s\S]+?\[  8\][\s\S]+?\n", "", case, 1)
            tc_groups = re.findall("(\[  4\][\s\S]+?\n\[SUM\][\s\S]+?\n)- - -", split_content)
            for tc in tc_groups:
                content = re.sub("\(omitted\)|\[|\]", "", tc)
                merges = [[2, 3], [4, 5], [6, 7], [9, 10]]
                tableContent[parser_log.TABLE] = ""
                tableContent[parser_log.I_TABLE] = parser_log.parseMergeTable(content, "\\s{1,}", merges, adds=[[11, 6]])
                tableContent[parser_log.CENTER_TOP] = ""
                tables.append(copy.deepcopy(tableContent))
            nowContent = re.sub("(\[ ID\][\s\S]+?\n)(- ){3,}", "", split_content)
            tc_groups = re.search("(\[ ID\] [\s\S]+\n\[SUM\][\s\S]+?\n)", nowContent)
            if tc_groups is not None:
                content = re.sub("\(omitted\)|\[|\]", "", tc_groups.groups()[0])
                merges = [[2, 3], [4, 5], [6, 7]]
                tableContent[parser_log.TABLE] = ""
                tableContent[parser_log.I_TABLE] = parser_log.parseMergeTable(content, "\\s{1,}", merges, [1],
                                                                  adds=[[3, 5], [5, 5], [7, 5], [9, 5], [11, 5],
                                                                        [13, 5], [15, 5], [17, 5], [19, 5], [21, 5],
                                                                        [23, 5]])
                tableContent[parser_log.CENTER_TOP] = ""
                tables.append(copy.deepcopy(tableContent))

        if testcase == "iperf UDP_sin_1_tx":
            center_top = re.search("Connecting[\s\S]+?\n", case)
            if center_top is not None:
                tableContent[parser_log.CENTER_TOP] = center_top.group(0)
            tc = re.search("(\[ ID\][\s\S]+\n)(- ){3,}", case)
            if tc is not None:
                content = re.sub("\(omitted\)|\[|\]", "", tc.groups()[0])
                title_merges = [[5, 6]]
                merges = [[2, 3], [4, 5], [6, 7]]
                tableContent[parser_log.TABLE] = parser_log.parseMergeTitleTable(content, "\\s{1,}", merges, title_merges)
                tables.append(copy.deepcopy(tableContent))

            tc = re.search("- - -\n(\[ ID\][\s\S]+\n)[\n\r]{1,}", case)
            if tc is not None:
                content = re.sub("\(omitted\)|\[|\]", "", tc.groups()[0])
                title_merges = [[6, 7]]
                merges = [[2, 3], [4, 5], [6, 7], [8, 9]]
                tableContent[parser_log.TABLE] = parser_log.parseMergeTitleTable(content, "\\s{1,}", merges, title_merges, [3])
                tableContent[parser_log.CENTER_TOP] = ""
                tables.append(copy.deepcopy(tableContent))

        if testcase == "iperf UDP_sin_1_rx":
            center_top = re.search("Connecting[\s\S]+?\n", case)
            if center_top is not None:
                tableContent[parser_log.CENTER_TOP] = center_top.group(0)
            tc = re.search("(\[ ID\][\s\S]+\n)(- ){3,}", case)
            if tc is not None:
                content = re.sub("\(omitted\)|\[|\]", "", tc.groups()[0])
                title_merges = [[6, 7]]
                merges = [[2, 3], [4, 5], [6, 7], [8, 9], [10, 11]]
                tableContent[parser_log.TABLE] = parser_log.parseMergeTitleTable(content, "\\s{1,}", merges, title_merges)
                tables.append(copy.deepcopy(tableContent))

            tc = re.search("- - -\n(\[ ID\][\s\S]+\n)[\n\r]{1,}", case)
            if tc is not None:
                content = re.sub("\(omitted\)|\[|\]", "", tc.groups()[0])
                title_merges = [[6, 7]]
                merges = [[2, 3], [4, 5], [6, 7], [8, 9], [10, 11]]
                tableContent[parser_log.TABLE] = parser_log.parseMergeTitleTable(content, "\\s{1,}", merges, title_merges,
                                                                     [3, 5, 7])
                tableContent[parser_log.CENTER_TOP] = ""
                tables.append(copy.deepcopy(tableContent))

        if testcase == "iperf UDP_sin_3_tx":
            center_top = re.search("Connecting[\s\S]+?\n", case)
            if center_top is not None:
                tableContent[parser_log.CENTER_TOP] = center_top.group(0)
            tc = re.search("(\[ ID\][\s\S]+?\n)(- ){3,}", case)
            if tc is not None:
                content = re.sub("\(omitted\)|\[|\]", "", tc.groups()[0])
                title_merges = [[5, 6]]
                merges = [[2, 3], [4, 5], [6, 7]]
                tableContent[parser_log.TABLE] = parser_log.parseMergeTitleTable(content, "\\s{1,}", merges, title_merges, )
                tables.append(copy.deepcopy(tableContent))
            split_content = re.sub("\[  4\][\s\S]+?\[  8\][\s\S]+?\n", "", case, 1)
            tc_groups = re.findall("(\[  4\][\s\S]+?\n\[SUM\][\s\S]+?\n)- - -", split_content)
            for tc in tc_groups:
                content = re.sub("\(omitted\)|\[|\]", "", tc)
                merges = [[2, 3], [4, 5], [6, 7]]
                tableContent[parser_log.TABLE] = ""
                tableContent[parser_log.I_TABLE] = parser_log.parseMergeTable(content, "\\s{1,}", merges)
                tableContent[parser_log.CENTER_TOP] = ""
                tables.append(copy.deepcopy(tableContent))
            nowContent = re.sub("(\[ ID\][\s\S]+?\n)(- ){3,}", "", split_content)
            tc_groups = re.search("(\[ ID\] [\s\S]+\n\[SUM\][\s\S]+?\n)", nowContent)
            if tc_groups is not None:
                content = re.sub("\(omitted\)|\[|\]", "", tc_groups.groups()[0])
                title_merges = [[6, 7]]
                merges = [[2, 3], [4, 5], [6, 7], [8, 9], [10, 11]]
                tableContent[parser_log.TABLE] = ""
                tableContent[parser_log.I_TABLE] = parser_log.parseMergeTitleTable(content, "\\s{1,}", merges, title_merges,
                                                                       [3, 5, 7])
                tableContent[parser_log.CENTER_TOP] = ""
                tables.append(copy.deepcopy(tableContent))

        if testcase == "iperf UDP_sin_3_rx":
            center_top = re.search("Connecting[\s\S]+?\n", case)
            if center_top is not None:
                tableContent[parser_log.CENTER_TOP] = center_top.group(0)
            tc = re.search("(\[ ID\][\s\S]+?\n)(- ){3,}", case)
            if tc is not None:
                content = re.sub("\(omitted\)|\[|\]", "", tc.groups()[0])
                title_merges = [[6, 7]]
                merges = [[2, 3], [4, 5], [6, 7], [8, 9], [10, 11]]
                tableContent[parser_log.TABLE] = parser_log.parseMergeTitleTable(content, "\\s{1,}", merges, title_merges, )
                tables.append(copy.deepcopy(tableContent))
            split_content = re.sub("\[  4\][\s\S]+?\[  8\][\s\S]+?\n", "", case, 1)
            tc_groups = re.findall("(\[  4\][\s\S]+?\n\[SUM\][\s\S]+?\n)- - -", split_content)
            for tc in tc_groups:
                content = re.sub("\(omitted\)|\[|\]", "", tc)
                merges = [[2, 3], [4, 5], [6, 7], [8, 9], [10, 11]]
                tableContent[parser_log.TABLE] = ""
                tableContent[parser_log.I_TABLE] = parser_log.parseMergeTable(content, "\\s{1,}", merges)
                tableContent[parser_log.CENTER_TOP] = ""
                tables.append(copy.deepcopy(tableContent))
            nowContent = re.sub("(\[ ID\][\s\S]+?\n)(- ){3,}", "", split_content)
            tc_groups = re.search("(\[ ID\] [\s\S]+\n\[SUM\][\s\S]+?\n)", nowContent)
            if tc_groups is not None:
                content = re.sub("\(omitted\)|\[|\]", "", tc_groups.groups()[0])
                title_merges = [[6, 7]]
                merges = [[2, 3], [4, 5], [6, 7], [8, 9], [10, 11]]
                tableContent[parser_log.TABLE] = ""
                tableContent[parser_log.I_TABLE] = parser_log.parseMergeTitleTable(content, "\\s{1,}", merges, title_merges,
                                                                       [3, 5, 7])
                tableContent[parser_log.CENTER_TOP] = ""
                tables.append(copy.deepcopy(tableContent))

        if testcase == "iperf UDP_sin_5_tx":
            center_top = re.search("Connecting[\s\S]+?\n", case)
            if center_top is not None:
                tableContent[parser_log.CENTER_TOP] = center_top.group(0)
            tc = re.search("(\[ ID\][\s\S]+?\n)(- ){3,}", case)
            if tc is not None:
                content = re.sub("\(omitted\)|\[|\]", "", tc.groups()[0])
                title_merges = [[5, 6]]
                merges = [[2, 3], [4, 5], [6, 7]]
                tableContent[parser_log.TABLE] = parser_log.parseMergeTitleTable(content, "\\s{1,}", merges, title_merges, )
                tables.append(copy.deepcopy(tableContent))
            split_content = re.sub("\[  4\][\s\S]+?\[  8\][\s\S]+?\n", "", case, 1)
            tc_groups = re.findall("(\[  4\][\s\S]+?\n\[SUM\][\s\S]+?\n)- - -", split_content)
            for tc in tc_groups:
                content = re.sub("\(omitted\)|\[|\]", "", tc)
                merges = [[2, 3], [4, 5], [6, 7]]
                tableContent[parser_log.TABLE] = ""
                tableContent[parser_log.I_TABLE] = parser_log.parseMergeTable(content, "\\s{1,}", merges)
                tableContent[parser_log.CENTER_TOP] = ""
                tables.append(copy.deepcopy(tableContent))
            nowContent = re.sub("(\[ ID\][\s\S]+?\n)(- ){3,}", "", split_content)
            tc_groups = re.search("(\[ ID\] [\s\S]+\n\[SUM\][\s\S]+?\n)", nowContent)
            if tc_groups is not None:
                content = re.sub("\(omitted\)|\[|\]", "", tc_groups.groups()[0])
                title_merges = [[6, 7]]
                merges = [[2, 3], [4, 5], [6, 7], [8, 9], [10, 11]]
                tableContent[parser_log.TABLE] = ""
                tableContent[parser_log.I_TABLE] = parser_log.parseMergeTitleTable(content, "\\s{1,}", merges, title_merges,
                                                                       [3, 5, 7, 11])
                tableContent[parser_log.CENTER_TOP] = ""
                tables.append(copy.deepcopy(tableContent))

        if testcase == "iperf UDP_sin_5_rx":
            center_top = re.search("Connecting[\s\S]+?\n", case)
            if center_top is not None:
                tableContent[parser_log.CENTER_TOP] = center_top.group(0)
            tc = re.search("(\[ ID\][\s\S]+?\n)(- ){3,}", case)
            if tc is not None:
                content = re.sub("\(omitted\)|\[|\]", "", tc.groups()[0])
                title_merges = [[6, 7]]
                merges = [[2, 3], [4, 5], [6, 7], [8, 9], [10, 11]]
                tableContent[parser_log.TABLE] = parser_log.parseMergeTitleTable(content, "\\s{1,}", merges, title_merges, )
                tables.append(copy.deepcopy(tableContent))
            split_content = re.sub("\[  4\][\s\S]+?\[  8\][\s\S]+?\n", "", case, 1)
            tc_groups = re.findall("(\[  4\][\s\S]+?\n\[SUM\][\s\S]+?\n)- - -", split_content)
            for tc in tc_groups:
                content = re.sub("\(omitted\)|\[|\]", "", tc)
                merges = [[2, 3], [4, 5], [6, 7], [8, 9], [10, 11]]
                tableContent[parser_log.TABLE] = ""
                tableContent[parser_log.I_TABLE] = parser_log.parseMergeTable(content, "\\s{1,}", merges)
                tableContent[parser_log.CENTER_TOP] = ""
                tables.append(copy.deepcopy(tableContent))
            nowContent = re.sub("(\[ ID\][\s\S]+?\n)(- ){3,}", "", split_content)
            tc_groups = re.search("(\[ ID\] [\s\S]+\n\[SUM\][\s\S]+?\n)", nowContent)
            if tc_groups is not None:
                content = re.sub("\(omitted\)|\[|\]", "", tc_groups.groups()[0])
                title_merges = [[6, 7]]
                merges = [[2, 3], [4, 5], [6, 7], [8, 9], [10, 11]]
                tableContent[parser_log.TABLE] = ""
                tableContent[parser_log.I_TABLE] = parser_log.parseMergeTitleTable(content, "\\s{1,}", merges, title_merges,
                                                                       [3, 5, 7, 11])
                tableContent[parser_log.CENTER_TOP] = ""
                tables.append(copy.deepcopy(tableContent))

        if testcase == "iperf UDP_sin_10_tx":
            center_top = re.search("Connecting[\s\S]+?\n", case)
            if center_top is not None:
                tableContent[parser_log.CENTER_TOP] = center_top.group(0)
            tc = re.search("(\[ ID\][\s\S]+?\n)(- ){3,}", case)
            if tc is not None:
                content = re.sub("\(omitted\)|\[|\]", "", tc.groups()[0])
                title_merges = [[5, 6]]
                merges = [[2, 3], [4, 5], [6, 7]]
                tableContent[parser_log.TABLE] = parser_log.parseMergeTitleTable(content, "\\s{1,}", merges, title_merges, )
                tables.append(copy.deepcopy(tableContent))
            split_content = re.sub("\[  4\][\s\S]+?\[  8\][\s\S]+?\n", "", case, 1)
            tc_groups = re.findall("(\[  4\][\s\S]+?\n\[SUM\][\s\S]+?\n)- - -", split_content)
            for tc in tc_groups:
                content = re.sub("\(omitted\)|\[|\]", "", tc)
                merges = [[2, 3], [4, 5], [6, 7]]
                tableContent[parser_log.TABLE] = ""
                tableContent[parser_log.I_TABLE] = parser_log.parseMergeTable(content, "\\s{1,}", merges)
                tableContent[parser_log.CENTER_TOP] = ""
                tables.append(copy.deepcopy(tableContent))
            nowContent = re.sub("(\[ ID\][\s\S]+?\n)(- ){3,}", "", split_content)
            tc_groups = re.search("(\[ ID\] [\s\S]+\n\[SUM\][\s\S]+?\n)", nowContent)
            if tc_groups is not None:
                content = re.sub("\(omitted\)|\[|\]", "", tc_groups.groups()[0])
                title_merges = [[6, 7]]
                merges = [[2, 3], [4, 5], [6, 7], [8, 9], [10, 11]]
                tableContent[parser_log.TABLE] = ""
                tableContent[parser_log.I_TABLE] = parser_log.parseMergeTitleTable(content, "\\s{1,}", merges, title_merges,
                                                                       [3, 5, 7, 11, 13, 15, 17, 19, 21, 23])
                tableContent[parser_log.CENTER_TOP] = ""
                tables.append(copy.deepcopy(tableContent))

        if testcase == "iperf UDP_sin_10_rx":
            center_top = re.search("Connecting[\s\S]+?\n", case)
            if center_top is not None:
                tableContent[parser_log.CENTER_TOP] = center_top.group(0)
            tc = re.search("(\[ ID\][\s\S]+?\n)(- ){3,}", case)
            if tc is not None:
                content = re.sub("\(omitted\)|\[|\]", "", tc.groups()[0])
                title_merges = [[6, 7]]
                merges = [[2, 3], [4, 5], [6, 7], [8, 9], [10, 11]]
                tableContent[parser_log.TABLE] = parser_log.parseMergeTitleTable(content, "\\s{1,}", merges, title_merges, )
                tables.append(copy.deepcopy(tableContent))
            split_content = re.sub("\[  4\][\s\S]+?\[  8\][\s\S]+?\n", "", case, 1)
            tc_groups = re.findall("(\[  4\][\s\S]+?\n\[SUM\][\s\S]+?\n)- - -", split_content)
            for tc in tc_groups:
                content = re.sub("\(omitted\)|\[|\]", "", tc)
                merges = [[2, 3], [4, 5], [6, 7], [8, 9], [10, 11]]
                tableContent[parser_log.TABLE] = ""
                tableContent[parser_log.I_TABLE] = parser_log.parseMergeTable(content, "\\s{1,}", merges)
                tableContent[parser_log.CENTER_TOP] = ""
                tables.append(copy.deepcopy(tableContent))
            nowContent = re.sub("(\[ ID\][\s\S]+?\n)(- ){3,}", "", split_content)
            tc_groups = re.search("(\[ ID\] [\s\S]+\n\[SUM\][\s\S]+?\n)", nowContent)
            if tc_groups is not None:
                content = re.sub("\(omitted\)|\[|\]", "", tc_groups.groups()[0])
                title_merges = [[6, 7]]
                merges = [[2, 3], [4, 5], [6, 7], [8, 9], [10, 11]]
                tableContent[parser_log.TABLE] = ""
                tableContent[parser_log.I_TABLE] = parser_log.parseMergeTitleTable(content, "\\s{1,}", merges, title_merges,
                                                                       [3, 5, 7, 11, 13, 15, 17, 19, 21, 23])
                tableContent[parser_log.CENTER_TOP] = ""
                tables.append(copy.deepcopy(tableContent))

        caseDict[parser_log.TABLES] = tables
        result.append(caseDict)
    outfp.write(json.dumps(result))
    return result
if __name__ == "__main__":
    infile = "iperf_output.log"
    outfile = "iperf_json.txt"
    outfp = open(outfile, "a+")
    iperf(infile, outfp)
    outfp.close()
