#ifndef TASKS_MULTISET_FORBID_REFORMULATED_TASK_H
#define TASKS_MULTISET_FORBID_REFORMULATED_TASK_H

#include "delegating_task.h"
#include "../utils/logging.h"

#include <vector>
#include <unordered_map>

/*
  The class reformulates a planning task to forbid any plan
  that, treated as a multiset, is a subset of the given multiset.
  This is done by tracking the number of applications for each
  action in the given multiset.
 */

namespace extra_tasks {
class MultisetForbidReformulatedTask : public tasks::DelegatingTask {
    const std::unordered_map<int, int> forbidding_multiset;
    bool change_operator_names;

	int operators_on_plan;
	std::vector<int> initial_state_values;
	std::vector<int> plan_operators_indexes;
    std::unordered_map<int, int> op_no_to_var_no;
    std::vector<int> var_no_to_op_no;
    std::vector<int> plan_operators_following_effs;

	bool is_operator_on_plan(int op_no) const;
	int get_number_appearances(int op_index) const;

	int get_parent_op_index(int index) const;
	int get_op_type(int index) const;

	int get_possible_var_index() const;
	int get_following_var_index(int op_index) const;
    int get_following_operator_pre(int op_index) const;
    int get_following_operator_eff(int op_index) const;

public:
	MultisetForbidReformulatedTask(
        const std::shared_ptr<AbstractTask> parent,
        std::unordered_map<int, int>& multiset, bool change_operator_names=false);
    virtual ~MultisetForbidReformulatedTask() override = default;

    virtual int get_num_variables() const override;
    virtual std::string get_variable_name(int var) const override;
    virtual int get_variable_domain_size(int var) const override;
    virtual int get_variable_axiom_layer(int var) const override;
    virtual int get_variable_default_axiom_value(int var) const override;
    virtual std::string get_fact_name(const FactPair &fact) const override;
    virtual bool are_facts_mutex(
        const FactPair &fact1, const FactPair &fact2) const override;

    virtual int get_operator_cost(int index, bool is_axiom) const override;
    virtual std::string get_operator_name(int index, bool is_axiom) const override;
    virtual int get_num_operators() const override;
    virtual int get_num_operator_preconditions(int index, bool is_axiom) const override;
    virtual FactPair get_operator_precondition(
        int op_index, int fact_index, bool is_axiom) const override;
    virtual int get_num_operator_effects(int op_index, bool is_axiom) const override;
    virtual int get_num_operator_effect_conditions(
        int op_index, int eff_index, bool is_axiom) const override;
    virtual FactPair get_operator_effect_condition(
        int op_index, int eff_index, int cond_index, bool is_axiom) const override;
    virtual FactPair get_operator_effect(
        int op_index, int eff_index, bool is_axiom) const override;

    virtual int get_num_goals() const override;
    virtual FactPair get_goal_fact(int index) const override;

    virtual std::vector<int> get_initial_state_values() const override;
    virtual void convert_state_values_from_parent(
        std::vector<int> &values) const override;

};
}

#endif
