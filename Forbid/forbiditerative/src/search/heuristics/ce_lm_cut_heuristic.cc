#include "ce_lm_cut_heuristic.h"

#include "ce_lm_cut_landmarks.h"

#include "../option_parser.h"
#include "../plugin.h"
#include "../task_proxy.h"

#include "../task_utils/task_properties.h"
#include "../utils/logging.h"
#include "../utils/memory.h"

#include <iostream>

using namespace std;

namespace ce_lm_cut_heuristic {
CELandmarkCutHeuristic::CELandmarkCutHeuristic(const Options &opts)
    : Heuristic(opts),
      landmark_generator(utils::make_unique_ptr<CELandmarkCutLandmarks>(task_proxy)) {
    utils::g_log << "Initializing landmark cut heuristic..." << endl;
}

CELandmarkCutHeuristic::~CELandmarkCutHeuristic() {
}

int CELandmarkCutHeuristic::compute_heuristic(const State &ancestor_state) {
    State state = convert_ancestor_state(ancestor_state);
    int total_cost = 0;
    bool dead_end = landmark_generator->compute_landmarks(
        state,
        [&total_cost](int cut_cost) {total_cost += cut_cost;},
        nullptr);

    if (dead_end)
        return DEAD_END;
    return total_cost;
}

static shared_ptr<Heuristic> _parse(OptionParser &parser) {
    parser.document_synopsis("Landmark-cut heuristic", "");
    parser.document_language_support("action costs", "supported");
    parser.document_language_support("conditional effects", "supported");
    parser.document_language_support("axioms", "not supported");
    parser.document_property("admissible", "yes");
    parser.document_property("consistent", "no");
    parser.document_property("safe", "yes");
    parser.document_property("preferred operators", "no");

    Heuristic::add_options_to_parser(parser);
    Options opts = parser.parse();
    if (parser.dry_run())
        return nullptr;
    else
        return make_shared<CELandmarkCutHeuristic>(opts);
}

static Plugin<Evaluator> _plugin("celmcut", _parse);
}
