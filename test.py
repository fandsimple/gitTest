
# -*- coding:utf-8 -*-


class CodeSecIssue(IssueTemplate):
    """
        代码泄露检索：
        github：
            code search api
    """

    def __init__(self, result_inst):
        super().__init__(result_inst)
        self.domain = result_inst.task_url
        self.category = result_inst.category
        self.task_url = result_inst.task_url
        self.web_url = result_inst.web_url
        self.task_id = result_inst.task_id
        self.req_ip = result_inst.req_ip
        self.log_print = result_inst.log_print
        self.speed = result_inst.speed
        self.main_task_id = result_inst.main_task_id
        self.rule_list = result_inst.rule_list
        self.rule_id_list = [rule.get("indicator_dict_id") for rule in result_inst.rule_list]
        self.scan_control = result_inst.scan_control
        self.github_params_length = result_inst.config.cfg['codesec_config']['params_length']

    def issue(self):
        res_list = []
        res_rule_list = self.parse_codesec_config()
        self.log_print.logger.debug("=====规则列表=======" + str(res_rule_list))
        # 判断该指标是否不进行扫描
        if not self.is_exist(INDICATOR_248, self.rule_id_list):
            return res_list
        params_dict_list = []
        for _rule in res_rule_list:
            params_dict_list.append({
                "q": _rule,
                "page": "1",
                "per_page": "10"
            })

        # # 多进程进行请求
        # response_list = []
        # with ThreadPoolExecutor(max_workers=5) as executor:
        #     future_result_list = [executor.submit(self.fetch_leaked_content_response, _params_dict) for _params_dict in params_dict_list]
        #     for future in concurrent.futures.as_completed(future_result_list):
        #         res = future.result()
        #         response_list.append(res)
        # for _response in response_list: # 解析结果，提取指标
        #     res_list.extend(self.extract_indicators(_response))

        # =======测试打开=================
        response = self.fetch_leaked_content_response({
            "q": "class",
            "page": "1",
            "per_page": "10"
        })
        # content = response.json()
        # print("======================================")
        # print(content)
        # print("======================================")
        # res_data = json.loads(content)
        res_list = self.extract_indicators(response)
        # =======测试打开=================
        return res_list

    def extract_indicators(self, response):
        res_dict = response.json()
        item_list = res_dict.get("items")
        now = self.generate_create_time()
        # 需要提取的字段至少拥有：
        # 必须（代码仓库名称	代码项目名称	所属组织	组织类型）
        # 非必须（命中关键字	来源	泄露地址	作者	语言	资产标签）
        # 李季（文件、检测时间、命中的上下文信息（50字符））
        result_indicator_item_list = []
        for item in item_list:
            text_matches_list = item.get("text_matches", [])
            keyword_info_list = []
            for text_matche_dict in text_matches_list:  # 同时可能匹配到多个关键字
                matches = text_matche_dict.get("matches", [])
                content = text_matche_dict.get("fragment", '')
                keword_info_dict = {
                    "content": content,
                }
                keword_list = []
                for _match in matches:
                    keword_list.append(_match.get("text", ''))
                keword_info_dict['keyword_list'] = keword_list
                keyword_info_list.append(keword_info_dict)

            for keword_info in keyword_info_list:  # 补充其他信息
                indicator_item_temp = {
                    "task_url": self.task_url,
                    "indicator_dict_id": INDICATOR_248,
                    "indicator_dict_name": "检测到源代码信息泄露",
                    "repos_name": item.get("repository", {}).get("full_name"),
                    "code_project_name": item.get("repository", {}).get("name"),
                    "source": "github",
                    "author": item.get("repository", {}).get("owner", {}).get("login"),
                    "programming_language": "",  # 接口无法获取
                    "create_time": now,
                    "html_url": item.get("html_url", ""),  # 泄露代码的github地址
                    "file_name": item.get("name", ""),
                    "keyword_list": keword_info.get("keyword_list"),
                    "content": keword_info.get("content"),  # 命中关键字上下文信息，是否要保留
                }
                result_indicator_item_list.append(indicator_item_temp)
        return result_indicator_item_list

    def fetch_leaked_content_response(self, params_dict):
        response = wrap_common_request(service='github_code_search', target=params_dict, main_task_id=self.main_task_id,
                                       enable=True)
        return response

    def is_exist(self, indicator_dict_id, rule_id_list):
        if int(indicator_dict_id) in rule_id_list or str(indicator_dict_id) in rule_id_list:
            return True
        return False

    def parse_codesec_config(self):
        '''
        解析用户下发规则，生成规则组进行请求
        '''
        codesec_config = self.scan_control.get_codesec_config()
        codesec_config = {
            # 或关系的
            "apiKey": {"keyword": ["key1", "key2"], 'operate': "OR"},
            "password": {"keyword": ["pwd1", "pwd2"], "operate": "OR"},

            # 且关系的
            "AND": {"keyword": ["AND1", "AND2"], "operate": "AND"},

            # 排除在外的 与上面形成且关系
            "exclude_repo": {"keyword": ["repo1", "repo2"], "operate": "AND"},
            "exclude_file": {"keyword": ["file1", "file2"], "operate": "AND"},
            "exclude_file_type": {"keyword": ["file_type1", "file_type2"], "operate": "AND"},
            "exclude_path": {"keyword": ["path1", "path2"], "operate": "AND"},
            "exclude_user": {"keyword": ["user1", "user2"], "operate": "AND"}
        }

        # 基本规则
        basic_rule = {"keyword": [self.domain], "operate": "OR"}
        codesec_config['basic_rule'] = basic_rule

        # 提取或关系的词
        exclude_repo = self.generate_rule(codesec_config.get('exclude_repo', {}).get("keyword"), 'repo')
        self.log_print.info("===========exclude_repo===========%s" % str(exclude_repo))
        exclude_file = self.generate_rule(codesec_config.get('exclude_file', {}).get("keyword"), 'file')
        exclude_file_type = self.generate_rule(codesec_config.get('exclude_file_type', {}).get("keyword"), 'file_type')
        exclude_path = self.generate_rule(codesec_config.get('exclude_path', {}).get("keyword"), 'path')
        exclude_user = self.generate_rule(codesec_config.get('exclude_user', {}).get("keyword"), 'user')
        # 进行相加拼接
        exclude_filter = exclude_repo + " " + exclude_file + " " + exclude_file_type + " " + exclude_path + " " + exclude_user
        operate_type_and_rule_list = []
        operate_type_or_rule_origin_list = []
        for key, rule_info in codesec_config.items():
            if rule_info.get("operate") == "AND":
                operate_type_and_rule_list.append(self.generate_rule(rule_info.get('keyword'), "content"))
            elif rule_info.get("operate") == "OR":
                operate_type_or_rule_origin_list.extend(rule_info.get('keyword'))

        operate_type_and_rule = " AND ".join(operate_type_and_rule_list)
        and_rule = operate_type_and_rule + "AND" + exclude_filter
        if len(and_rule) > self.github_params_length:  # 基本参数已经超出限制长度了
            self.log_print.info(
                "基本参数已经超出限制长度了,基本参数:%s, 长度：%s, 配置长度:%s" % (and_rule, str(len(and_rule)), str(self.github_params_length)))
            return None
        # 进行拆分处理
        remain_length = self.github_params_length - len(and_rule)
        count = 0
        split_result_list = []
        a="2c6f75f3-b2f6-4f63-821a-e1cde6583e89"
        split_list_temp = []
        for operate_type_or_rule_origin_item in operate_type_or_rule_origin_list:
            if count + len(operate_type_or_rule_origin_item) <= remain_length:
                split_list_temp.append(operate_type_or_rule_origin_item)
                count += len(operate_type_or_rule_origin_item)
            else:
                split_result_list.append(copy.deepcopy(split_list_temp))
                split_list_temp = []
                split_list_temp.append(operate_type_or_rule_origin_item)
                count = len(operate_type_or_rule_origin_item)
        # 构造规则，进行输出
        res_rule_list = []
        for split_result_item in split_result_list:
            temp_rule = self.generate_rule(split_result_item, "content", "OR")
            res_rule_list.append(temp_rule + "AND" + and_rule)
        return res_rule_list

    def generate_rule(self, rule_list, type, operate="AND"):
        '''
        根据规则列表，生成规则字符串
        '''
        res_rule = ""
        if type == "repo":
            for rule_item in rule_list:
                res_rule += "NOT repo:%s %s " % (rule_item, operate)
            # res_rule = res_rule.strip('%s ' % operate)
            # res_rule = res_rule.strip('%s ' % operate)
        elif type == "file":
            for rule_item in rule_list:
                res_rule += "NOT path:%s " % rule_item
            res_rule = res_rule.strip('%s ' % operate)
        elif type == "file_type":
            for rule_item in rule_list:
                res_rule += "NOT path:*.%s " % rule_item
            res_rule = res_rule.strip('%s ' % operate)
        elif type == "path":
            for rule_item in rule_list:
                res_rule += "NOT path:%s " % rule_item
            res_rule = res_rule.strip('%s ' % operate)
        elif type == "user":
            for rule_item in rule_list:
                res_rule += "NOT user:%s " % rule_item
            res_rule = res_rule.strip('%s ' % operate)
        elif type == "content":
            for rule_item in rule_list:
                res_rule += "content:%s " % rule_item
            res_rule = res_rule.strip('%s ' % operate)
            a = "2c6f75f3-b2f6-4f63-821a-e1cde6583e89"
        return res_rule


if __name__ == '__main__':
    pass
