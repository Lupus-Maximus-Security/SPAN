# Copyright 2017 Quark Security, Inc.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# * Redistributions of source code must retain the above copyright notice, this
#   list of conditions and the following disclaimer.
#
# * Redistributions in binary form must reproduce the above copyright notice,
#   this list of conditions and the following disclaimer in the documentation
#   and/or other materials provided with the distribution.
#
# * Neither the name of the copyright holder nor the names of its
#   contributors may be used to endorse or promote products derived from
#   this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

__version__ = "1.0.0"

from .span import *
from .domain_categories import DomainCategories
from .indexed_terulequery import *
from .domain_summary_to_word import *

__all__ = [
    "__version__",
    # span.span — core policy API
    "load_policy",
    "load_policies_from_config",
    "Policy",
    "Type",
    "TypeAttribute",
    "wrap",
    "domain_summary_raw",
    "collect_types",
    "filter_types",
    "type_names",
    "cond_expr",
    "pp",
    # span.span — notebook/markdown helpers
    "pp_markdown",
    "as_str",
    "as_strset",
    "markdown_code_from_results",
    "markdown_list",
    # span.span — reference policy / diff
    "diff_to_html",
    "RefPolicySource",
    "load_refpolicy_source",
    # span.domain_categories
    "DomainCategories",
    # span.indexed_terulequery
    "build_index_if_needed",
    "get_type_names",
    # span.domain_summary_to_word
    "output_summary",
    "run",
]
